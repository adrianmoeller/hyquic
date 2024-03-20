#ifndef __HYBRID_FRAME_FORMAT_SPEC_H__
#define __HYBRID_FRAME_FORMAT_SPEC_H__

#define HYQUIC_REF_ID_MAX 63

struct hyquic_frame_format_spec_cont {
    uint16_t spec_length;
    uint8_t *spec_cursor;
    uint32_t content_length;
    uint8_t *content_cursor;
    uint32_t parsed_len;
    uint64_t ref_id_index[HYQUIC_REF_ID_MAX];
};

static inline int hyquic_ref_id_to_index(struct sock *sk, struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id, uint64_t length_value)
{
    if (ref_id > HYQUIC_REF_ID_MAX) {
        HQ_PR_ERR(sk, "reference ID too large");
        return -EINVAL;
    }
    if (cont->ref_id_index[ref_id - 1]) {
        HQ_PR_ERR(sk, "reference ID already in use");
        return -EINVAL;
    }
    cont->ref_id_index[ref_id - 1] = length_value;
    HQ_PR_DEBUG(sk, "done, ref_id=%u, length_value=%llu", ref_id, length_value);
    return 0;
}

static inline uint64_t hyquic_declared_length_from_index(struct sock *sk, struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    return cont->ref_id_index[ref_id - 1];
}

static inline int hyquic_parse_var_int_component(struct sock *sk, struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    uint64_t value;
    uint8_t value_len;

    value_len = quic_get_var(&cont->content_cursor, &cont->content_length, &value);
    if (!value_len) {
        HQ_PR_ERR(sk, "frame content not parsable (var-int expected)");
        return -EINVAL;
    }

    cont->spec_cursor++;
    cont->spec_length--;

    if (ref_id)
        return hyquic_ref_id_to_index(sk, cont, ref_id, value);
    
    HQ_PR_DEBUG(sk, "done, remain_spec_length=%u", cont->spec_length);
    return 0;
}

static inline int hyquic_parse_fix_len_component(struct sock *sk, struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    uint64_t length_value, declared_length;
    uint8_t length_value_len;
    uint32_t spec_length_tmp;

    cont->spec_cursor++;
    cont->spec_length--;

    spec_length_tmp = cont->spec_length;
    length_value_len = quic_get_var(&cont->spec_cursor, &spec_length_tmp, &length_value);
    if (!length_value_len) {
        HQ_PR_ERR(sk, "invalid specification (var-int expected)");
        return -EINVAL;
    }
    cont->spec_length = spec_length_tmp;

    if (ref_id) {
        if (length_value_len > 4) {
            HQ_PR_ERR(sk, "invalid specification (declared length too large)");
            return -EINVAL;
        }

        declared_length = quic_get_int(&cont->content_cursor, length_value);
        cont->content_length -= length_value;

        return hyquic_ref_id_to_index(sk, cont, ref_id, declared_length);
    } else {
        cont->content_cursor += length_value;
        cont->content_length -= length_value;
    }

    HQ_PR_DEBUG(sk, "done, length=%llu, remain_spec_length=%u", length_value, cont->spec_length);
    return 0;
}

static inline int hyquic_parse_mult_const_declared_len_component(struct sock *sk, struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    uint64_t declared_length;
    uint8_t constant;
    uint64_t product;

    if (!ref_id) {
        HQ_PR_ERR(sk, "invalid specification (no reference id)");
        return -EINVAL;
    }

    declared_length = hyquic_declared_length_from_index(sk, cont, ref_id);

    cont->spec_cursor++;
    cont->spec_length--;

    constant = quic_get_int(&cont->spec_cursor, 1);
    cont->spec_length--;

    if (!constant) {
        HQ_PR_ERR(sk, "invalid specification (constant must not be 0)");
        return -EINVAL;
    }

    if (!declared_length) {
        HQ_PR_DEBUG(sk, "done, ref_id=%u, decl_length=%llu, constant=%u, remain_spec_length=%u", ref_id, declared_length, constant, cont->spec_length);
        return 0;
    }

    product = declared_length * constant;

    cont->content_cursor += product;
    cont->content_length -= product;

    HQ_PR_DEBUG(sk, "done, ref_id=%u, decl_length=%llu, constant=%u, remain_spec_length=%u", ref_id, declared_length, constant, cont->spec_length);
    return 0;
}

static int hyquic_parse_next_spec_component(struct sock *sk, struct hyquic_frame_format_spec_cont *cont);

static inline int hyquic_parse_mult_scope_declared_len_component(struct sock *sk, struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    int err, i;
    uint64_t declared_length;
    uint8_t scope_length;
    struct hyquic_frame_format_spec_cont scope_cont;

    if (!ref_id) {
        HQ_PR_ERR(sk, "invalid specification (no reference id)");
        return -EINVAL;
    }

    declared_length = hyquic_declared_length_from_index(sk, cont, ref_id);

    cont->spec_cursor++;
    cont->spec_length--;

    scope_length = quic_get_int(&cont->spec_cursor, 1);
    cont->spec_length--;

    if (!scope_length) {
        HQ_PR_ERR(sk, "invalid specification (scope length must not be 0)");
        return -EINVAL;
    }
    
    if (!declared_length) {
        cont->spec_cursor += scope_length;
        cont->spec_length -= scope_length;
        HQ_PR_DEBUG(sk, "done, decl_length=%llu, scope_length=%u, remain_spec_length=%u", declared_length, scope_length, cont->spec_length);
        return 0;
    }


    for (i = 0; i < declared_length; i++) {
        scope_cont = (struct hyquic_frame_format_spec_cont) {
            .spec_length = scope_length,
            .spec_cursor = cont->spec_cursor,
            .content_length = cont->content_length,
            .content_cursor = cont->content_cursor
        };
        memcpy(scope_cont.ref_id_index, cont->ref_id_index, sizeof(cont->ref_id_index));

        while (scope_cont.spec_length > 0) {
            err = hyquic_parse_next_spec_component(sk, &scope_cont);
            if (err)
                return err;
        }

        cont->content_cursor = scope_cont.content_cursor;
        cont->content_length = scope_cont.content_length;
    }

    cont->spec_cursor += scope_length;
    cont->spec_length -= scope_length;

    HQ_PR_DEBUG(sk, "done, decl_length=%llu, scope_length=%u, remain_spec_length=%u", declared_length, scope_length, cont->spec_length);
    return 0;
}

static int hyquic_parse_next_spec_component(struct sock *sk, struct hyquic_frame_format_spec_cont *cont)
{
    uint8_t comp_header = *cont->spec_cursor;
    uint8_t comp_type = comp_header >> 6;
    uint8_t comp_ref_id = comp_header & 0x3F;

    switch (comp_type) {
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_VAR_INT:
        return hyquic_parse_var_int_component(sk, cont, comp_ref_id);
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_FIX_LEN:
        return hyquic_parse_fix_len_component(sk, cont, comp_ref_id);
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_MULT_CONST_DECL_LEN:
        return hyquic_parse_mult_const_declared_len_component(sk, cont, comp_ref_id);
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_MULT_SCOPE_DECL_LEN:
        return hyquic_parse_mult_scope_declared_len_component(sk, cont, comp_ref_id);
    default:
        return -EINVAL;
    }
}

static inline int hyquic_parse_frame_content(struct sock *sk, uint8_t *frame_content, uint32_t remaining_length, uint8_t *format_specification, uint16_t spec_length, uint32_t *parsed_length)
{
    int err;
    struct hyquic_frame_format_spec_cont cont = {
        .spec_length = spec_length,
        .spec_cursor = format_specification,
        .content_length = remaining_length,
        .content_cursor = frame_content,
        .ref_id_index = {0}
    };

    HQ_PR_DEBUG(sk, "spec_length=%u", spec_length);

    while (cont.spec_length > 0) {
        err = hyquic_parse_next_spec_component(sk, &cont);
        if (err)
            return err;
    }

    *parsed_length = cont.content_cursor - frame_content;
    HQ_PR_DEBUG(sk, "done, parsed=%u", *parsed_length);
    return 0;
}

#endif /* __HYBRID_FRAME_FORMAT_SPEC_H__ */
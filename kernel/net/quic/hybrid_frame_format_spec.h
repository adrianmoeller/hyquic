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

static inline int hyquic_ref_id_to_index(struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id, uint64_t length_value)
{
    if (ref_id > HYQUIC_REF_ID_MAX || cont->ref_id_index[ref_id - 1])
        return -EINVAL;
    cont->ref_id_index[ref_id - 1] = length_value;
    return 0;
}

static inline int hyquic_parse_var_int_component(struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    uint64_t value;
    uint8_t value_len;

    value_len = quic_get_var(&cont->content_cursor, &cont->content_length, &value);
    if (!value_len)
        return -EINVAL;

    cont->parsed_len += value_len;
    cont->spec_cursor++;
    cont->spec_length--;

    if (ref_id)
        return hyquic_ref_id_to_index(cont, ref_id, value);

    return 0;
}

static inline int hyquic_parse_fix_len_component(struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    uint64_t length_value, declared_length;
    uint8_t length_value_len;
    uint32_t spec_length_tmp;

    cont->spec_cursor++;
    cont->spec_length--;

    spec_length_tmp = cont->spec_length;
    length_value_len = quic_get_var(&cont->spec_cursor, &spec_length_tmp, &length_value);
    if (!length_value_len)
        return -EINVAL;
    cont->spec_length = spec_length_tmp;

    cont->parsed_len += length_value;
    cont->spec_cursor += length_value_len;
    cont->spec_length += length_value_len;

    if (ref_id) {
        if (length_value > 4)
            return -EINVAL;

        declared_length = quic_get_int(&cont->content_cursor, length_value);
        cont->content_length -= length_value;

        return hyquic_ref_id_to_index(cont, ref_id, declared_length);
    } else {
        cont->content_cursor += length_value;
        cont->content_length -= length_value;
    }

    return 0;
}

static inline int hyquic_parse_multi_const_declared_len_component(struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    uint64_t declared_length;
    uint8_t constant;
    uint64_t product;

    if (!ref_id)
        return -EINVAL;

    declared_length = cont->ref_id_index[ref_id];

    cont->spec_cursor++;
    cont->spec_length--;

    constant = quic_get_int(&cont->spec_cursor, 1);
    cont->spec_length--;

    if (!constant)
        return -EINVAL;

    if (!declared_length)
        return 0;

    product = declared_length * constant;

    cont->content_cursor += product;
    cont->content_length -= product;

    return 0;
}

static int hyquic_parse_next_spec_component(struct hyquic_frame_format_spec_cont *cont);

static inline int hyquic_parse_multi_scope_declared_len_component(struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    int err, i;
    uint64_t declared_length;
    uint8_t scope_length;
    struct hyquic_frame_format_spec_cont scope_cont;

    if (!ref_id)
        return -EINVAL;

    declared_length = cont->ref_id_index[ref_id];
    if (!declared_length)
        return -EINVAL;

    cont->spec_cursor++;
    cont->spec_length--;

    scope_length = quic_get_int(&cont->spec_cursor, 1);
    cont->spec_length--;

    if (!scope_length)
        return -EINVAL;
    
    if (!declared_length) {
        cont->spec_cursor += scope_length;
        cont->spec_length -= scope_length;
        return 0;
    }


    for (i = 0; i < declared_length; i++) {
        scope_cont = (struct hyquic_frame_format_spec_cont) {
            .spec_length = scope_length,
            .spec_cursor = cont->spec_cursor,
            .content_length = cont->content_length,
            .content_cursor = cont->content_cursor,
            .parsed_len = cont->parsed_len
        };
        memcpy(scope_cont.ref_id_index, cont->ref_id_index, sizeof(cont->ref_id_index));

        while (scope_cont.spec_length > 0) {
            err = hyquic_parse_next_spec_component(&scope_cont);
            if (err)
                return err;
        }

        cont->content_cursor = scope_cont.content_cursor;
        cont->content_length = scope_cont.content_length;
        cont->parsed_len = scope_cont.parsed_len;
    }

    cont->spec_cursor += scope_length;
    cont->spec_length -= scope_length;

    return 0;
}

static int hyquic_parse_next_spec_component(struct hyquic_frame_format_spec_cont *cont)
{
    uint8_t comp_header = *cont->spec_cursor;
    uint8_t comp_type = comp_header >> 6;
    uint8_t comp_ref_id = comp_header & 0x3F;

    switch (comp_type) {
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_VAR_INT:
        return hyquic_parse_var_int_component(cont, comp_ref_id);
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_FIX_LEN:
        return hyquic_parse_fix_len_component(cont, comp_ref_id);
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_MULTI_CONST_DECL_LEN:
        return hyquic_parse_multi_const_declared_len_component(cont, comp_ref_id);
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_MULTI_SCOPE_DECL_LEN:
        return hyquic_parse_multi_scope_declared_len_component(cont, comp_ref_id);
    default:
        return -EINVAL;
    }
}

static inline int hyquic_parse_frame_content(uint8_t *frame_content, uint32_t remaining_length, uint8_t *format_specification, uint16_t spec_length, uint32_t *parsed_length)
{
    int err;
    struct hyquic_frame_format_spec_cont cont = {
        .spec_length = spec_length,
        .spec_cursor = format_specification,
        .content_length = remaining_length,
        .content_cursor = frame_content,
        .parsed_len = 0,
        .ref_id_index = {0}
    };

    while (cont.spec_length > 0) {
        err = hyquic_parse_next_spec_component(&cont);
        if (err)
            return err;
    }

    *parsed_length = cont.parsed_len;
    return 0;
}

#endif /* __HYBRID_FRAME_FORMAT_SPEC_H__ */
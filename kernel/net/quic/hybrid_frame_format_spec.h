#ifndef __HYBRID_FRAME_FORMAT_SPEC_H__
#define __HYBRID_FRAME_FORMAT_SPEC_H__

struct hyquic_frame_format_spec_cont {
    uint16_t spec_length;
    const uint8_t *spec_cursor;
    const uint8_t *content_cursor;
    uint32_t parsed_len;
    uint64_t ref_id_index[63];
};

static inline hyquic_parse_var_int_component(struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    // TODO
}

static inline hyquic_parse_fix_len_component(struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    // TODO
}

static inline hyquic_parse_declared_len_component(struct hyquic_frame_format_spec_cont *cont, uint8_t ref_id)
{
    // TODO
}

static inline int hyquic_parse_next_spec_component(struct hyquic_frame_format_spec_cont *cont)
{
    uint8_t comp_header = *cont->spec_cursor;
    uint8_t comp_type = comp_header >> 6;
    uint8_t comp_ref_id = comp_header & 0x3F;

    switch (comp_type) {
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_VAR_INT:
        return hyquic_parse_var_int_component(cont, comp_ref_id);
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_FIX_LEN:
        return hyquic_parse_fix_len_component(cont, comp_ref_id);
    case HYQUIC_FRAME_FORMAT_SPEC_COMP_DECL_LEN:
        return hyquic_parse_declared_len_component(cont, comp_ref_id);
    default:
        return -EINVAL;
    }
}

static inline int hyquic_parse_frame_content(const uint8_t *frame_content, const uint8_t *format_specification, uint16_t spec_length, uint32_t *parsed_length)
{
    int err;
    struct hyquic_frame_format_spec_cont cont = {
        .spec_length = spec_length,
        .spec_cursor = format_specification,
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
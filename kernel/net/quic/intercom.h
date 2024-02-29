#ifndef __HYQUIC_INTERCOM_H__
#define __HYQUIC_INTERCOM_H__

static inline uint32_t hyquic_ic_get_int(uint8_t **pptr, uint8_t len)
{
    uint8_t *ptr = *pptr;
    uint32_t val = 0;

    switch (len) {
	case 1:
		val = *ptr;
		break;
	case 2:
		memcpy(&val, ptr, 2);
		break;
	case 4:
		memcpy(&val, ptr, 4);
		break;
	}
    *pptr = ptr + len;
	return val;
}

static inline void hyquic_ic_get_data(uint8_t **pptr, uint8_t *data, uint8_t len)
{
    uint8_t *ptr = *pptr;

    memcpy(data, ptr, len);
    *pptr = ptr + len;
}

static inline uint8_t* hyquic_ic_put_int(uint8_t *ptr, uint64_t val, uint8_t len)
{
    union {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
    } n;

    n.u64 = val;
    switch (len) {
    case 1:
		*ptr = n.u8;
		return ptr + 1;
	case 2:
		memcpy(ptr, &n.u16, 2);
		return ptr + 2;
	case 4:
		memcpy(ptr, &n.u32, 4);
		return ptr + 4;
	default:
		return NULL;
    }
}

static inline uint8_t* hyquic_ic_put_data(uint8_t *ptr, const uint8_t *data, uint32_t len)
{
    if (!len)
		return ptr;

	memcpy(ptr, data, len);
	return ptr + len;
}

#endif /* __HYQUIC_INTERCOM_H__ */
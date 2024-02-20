#include "hybrid.h"
#include <linux/slab.h>

void hyquic_init(struct hyquic_adapter *hyquic)
{
    hyquic->enabled = false;
    INIT_LIST_HEAD(&hyquic->transport_params_remote);
    INIT_LIST_HEAD(&hyquic->transport_params_local);
}

static void hyquic_transport_params_free(struct list_head *param_list)
{
    struct hyquic_transport_param *cursor, *tmp;

    list_for_each_entry_safe(cursor, tmp, param_list, list) {
        list_del(&cursor->list);
        kfree(cursor->param);
        kfree(cursor);
    }
}

void hyquic_free(struct hyquic_adapter *hyquic)
{
    hyquic_transport_params_free(&hyquic->transport_params_remote);
    hyquic_transport_params_free(&hyquic->transport_params_local);
}

inline void hyquic_transport_params_add(struct hyquic_transport_param *param, struct list_head *param_list)
{
    list_add_tail(&param->list, param_list);
}

size_t hyquic_transport_params_total_length(struct list_head *param_list)
{
    struct hyquic_transport_param *cursor;
	size_t total_length = 0;

	hyquic_transport_param_for_each(cursor, param_list) {
		total_length += cursor->length;
	}
    return total_length;
}
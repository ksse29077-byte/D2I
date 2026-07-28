#include "d2i_abi_v1.h"

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
__declspec(dllexport)
#endif
D2iStatus d2i_score_match_masks_v1(
    const uint8_t* match_masks,
    uint64_t item_count,
    uint16_t* scores,
    uint64_t score_capacity
) {
    if (match_masks == NULL || scores == NULL) {
        return D2I_INVALID_ARGUMENT;
    }
    if (score_capacity < item_count) {
        return D2I_BUFFER_TOO_SMALL;
    }
    for (uint64_t index = 0; index < item_count; ++index) {
        uint8_t mask = match_masks[index];
        if ((mask & UINT8_C(0xf8)) != 0) {
            return D2I_INVALID_ARGUMENT;
        }
        scores[index] = (uint16_t)(
            ((mask & UINT8_C(0x01)) != 0 ? 45 : 0)
            + ((mask & UINT8_C(0x02)) != 0 ? 45 : 0)
            + ((mask & UINT8_C(0x04)) != 0 ? 10 : 0)
        );
    }
    return D2I_OK;
}

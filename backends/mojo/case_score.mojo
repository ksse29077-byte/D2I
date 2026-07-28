"""Exports the isolated D2I case-score kernel through a C ABI."""

from memory import ImmutUnsafePointer, MutUnsafePointer


@export("d2i_score_match_masks_v1", ABI="C")
def score_match_masks(
    match_masks: ImmutUnsafePointer[UInt8, ImmutExternalOrigin],
    item_count: UInt64,
    scores: MutUnsafePointer[UInt16, MutExternalOrigin],
    score_capacity: UInt64,
) -> UInt32:
    """Scores three-bit match masks into caller-owned output.

    Args:
        match_masks: The borrowed input masks.
        item_count: The number of input masks.
        scores: The borrowed mutable score output.
        score_capacity: The number of available score elements.

    Returns:
        A D2I status code.

    Safety:
        Both pointers must remain valid for their declared lengths throughout
        this synchronous call.
    """
    if score_capacity < item_count:
        return UInt32(5)

    for index in range(Int(item_count)):
        var mask = match_masks[index]
        if mask & UInt8(0xF8) != UInt8(0):
            return UInt32(1)
        var score = UInt16(0)
        if mask & UInt8(0x01) != UInt8(0):
            score += UInt16(45)
        if mask & UInt8(0x02) != UInt8(0):
            score += UInt16(45)
        if mask & UInt8(0x04) != UInt8(0):
            score += UInt16(10)
        scores[index] = score

    return UInt32(0)

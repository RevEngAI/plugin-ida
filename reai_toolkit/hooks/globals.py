# These globals are used by the menu hooks/action handlers.
# Note: The reason for these existing is due to the update methods of action handlers not being able to safely query IDA's netstore.
# There is a possibility that when IDA is closing down, an update method is called and a netstore query is executed despite the underlying memory
# for the netstore being free'd, resulting in a UAF bug.

ANALYSIS_ID: int | None = None
BINARY_ID: int | None = None
MODEL_ID: int | None = None

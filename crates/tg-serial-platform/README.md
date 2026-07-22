# tg-serial-platform

Pinned cross-platform serial enumeration and guarded open adapter for TGCHECKM8.

The crate feeds operational observations into `tg-serial-doctor`, reserves the selected serial resource before opening, and releases the lease on any blocked result. No serial read or write command is issued.

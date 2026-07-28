# Threat Model

Keep untrusted content as data, reject raw secrets and oversized input, declare
all dependencies, and never add adapter, network, filesystem, process, or
privileged handles to the `Module` trait implementation.

# PITTv3 GUI

This crate provides a desktop GUI frontend for the PKI Interoperability Test Tool v3 (PITTv3),
offering a similar set of actions as the `pittv3` command line utility. The form mirrors the
command line options: values are assembled into a
[`Pittv3Args`](https://docs.rs/pittv3_lib/latest/pittv3_lib/args/struct.Pittv3Args.html) instance
and processed exactly as the CLI would process them. Argument values are saved to the pittv3.cfg
file in the .pittv3 folder beneath the user's home directory upon each run and restored at startup.

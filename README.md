# Intro

This works right now only on windows as I use windows specific code and i have not configured os based implementations.

## Dependencies

For firefox you will need to have nsstools installed and in your path. If you trust random people from the internet and don't want to build nsstools, you can get them from [here](https://bintray.com/cosminilie/Misc/download_file?file_path=nss-tools.msi). For java you need to have at least java 11 with keytool in your path and JAVA_HOME set.

To use the tool:

```cmd
c:\>certinstall url https://github.com
{"level":"info","ts":1583144603.9323955,"caller":"cmd/main.go:38","msg":"plucking certs","url":"https://github.com"}
{"level":"info","ts":1583144604.2647254,"caller":"cmd/main.go:46","msg":"found ca cert","commonName":"CA","url":"https://github.com"}
{"level":"info","ts":1583144604.2690482,"caller":"cmd/main.go:77","msg":"found java on the machine, attempting to install cert in cacerts"}
{"level":"info","ts":1583144605.1738913,"caller":"cmd/main.go:82","msg":"java cert installation completed successfully"}
{"level":"info","ts":1583144605.176893,"caller":"cmd/main.go:88","msg":"found firefox on the machine, attempting to install cert in certdb"}
{"level":"info","ts":1583144605.2262104,"caller":"cmd/main.go:93","msg":"firefox cert installation completed successfully"}
{"level":"info","ts":1583144608.5407617,"caller":"cmd/main.go:99","msg":"importing into windows cert store"}
{"level":"info","ts":1583144608.541762,"caller":"cmd/main.go:103","msg":"system cert installation completed successfully"}
c:\>
```

# TODO

- add support for linux and macos

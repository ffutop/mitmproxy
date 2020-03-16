# MITM Proxy

Man-In-The-Middle Proxy aim at expose [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format) (Pre)-Master-Secret for Wireshark analysis.

[TOC]

## Implement

```text

+----------+         Self Signed Root Certificate
|  Client  | <-----------------------------------------------+        
+----------+       Certificate Signed by Self Root CA        |
     ^                                                       v
     |                                                  +----------+
     X No more Direct Communicate                       |   MITM   |
     |                                                  +----------+ 
     v                                                       ^
+----------+                                                 |
|  Server  | <-----------------------------------------------+
+----------+    Trusted Communicate as normal Client-Server 

```

## Install

0. You should guarantee your machine has installed [Golang](https://golang.org/)

1. Clone Repository from GitHub
    ```shell script
    git clone git@github.com:ffutop/mitmproxy.git
    ```
   
2. Build and Install
    ```shell script
    cd ${YOUR-PATH-TO-MITMPROXY-DIRECTORY}; go build; go install;
    ```
   
3. Check Installation Result
    ```shell script
    mitmproxy --help
    ```

## Usage

1. prepare your [Root Certificate](https://en.wikipedia.org/wiki/Root_certificate) OR run `mitmproxy` to create a new Root Certificate
   
   newly created Root Certificate will be find at `$HOME/.mitm/`

2. make sure your OS trust Root Certificate which prepare at "STEP 1"

3. find `config.yaml.example` file, rename to `config.yaml` and edit

4. run mitmproxy
    ```shell script
    mitmproxy -config ${YOUR-PATH-TO-config-yaml}/config.yaml
    ```
   
5. follow [Wireshark: Using the (Pre)-Master-Secret](https://wiki.wireshark.org/TLS#Using_the_.28Pre.29-Master-Secret) and config your Wireshark configuration.

## Sample ScreenShot

![](http://img.ffutop.com/ABF46BAE-D441-40D7-964E-2925204C5A0F.png)

![](http://img.ffutop.com/B38CE94F-D501-473A-8719-ACF62545AD44.png)

## TODO

- [x] serve both http/https proxy on same port
- [ ] support auto modify MacOS global proxy config
   
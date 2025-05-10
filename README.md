# mTLS-ABAC-sample

## これは？

クライアント証明書の Subject を Lambda オーソライザーで解析し、バックエンドにリクエストヘッダーとして渡します。

バックエンドはこれでクライアント証明書の属性で、アクセスコントールができるかもしれません。

## 事前手順

検証用 CA 証明書と、クライアント証明書を準備しておいてください。

作った CA 証明書は`template_s3.yaml`で作成したバケットに格納しておいてください。

### CA 証明書作成

#### CA 用の秘密鍵の生成

```
openssl genrsa -out ca.key 4096
```

#### CA 証明書の作成

```
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/
C=JP/ST=Hokkaido/L=Sapporo/O=MyCompany/OU=IT/CN=MyPrivateCA"
```

### クライアント証明書の作成

#### tenant-A 用の秘密鍵の生成

```
openssl genrsa -out tenant-001.key 2048
```

#### 証明書署名要求(CSR)の作成

```
openssl req -new -key tenant-001.key -out tenant-001.csr -subj "/C=JP/ST=Hokkaido/L=Sapporo/O=MyCompany/OU=Finance/CN=tenant-001"
```

#### CA によるクライアント証明書への署名

```
openssl x509 -req -in tenant-001.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tenant-001.crt -days 365 -sha256
```

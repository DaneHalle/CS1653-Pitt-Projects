# File Interface

## `LFILES`
`TODO`

## `UPLOADF`: List 
* Request
```
{
    msg: "UPLOADF",
    objContents: [
        "path" / "destFile",
        "group",
        "token",
    ]
}
```
* If fails response
```
{
    msg: "FAIL-<ERROR>"
}
```
- FAIL-FILEEXISTS: File does not exists

* It succeeds it returns a `READY`
```
{
    msg: "READY"
}
```
* Client Sends `CHUNK`
```
{
    msg: "CHUNK",
    objContents: [
        "buf", // what was read in chunk
        "n",   // size of chunk
    ]
}
 - Do this continously until `fis.available()>0` or there is no more file to read
* For the final chunk we send a EOF
```
{
    msg: "EOF"
}
```
* Server returns status
```
{
    msg: "OK",
}
```

## `DOWNLOADF`: List 
* Request
```
{
    msg: "DOWNLOADF",
    objContents: [
        "remotePath",
        "token",
    ]
}
```
* Response: File is sending the `CHUNK`
```
{
    msg: "CHUNK",
    objContents: [
        "buf", // what was read in chunk
        "n",   // size of chunk
    ]
}
```
* Request: From Client Cont.
```
{
    msg: "DOWNLOADF",
    objContents: null
}
```
* If it is still `DOWNLOADF` then server sends `EOF`
```
{
    msg: "EOF",
    objContents: null
}
```
* And the client gives status
```
{
    msg: "OK",
    objContents: null
}
```

## `DELETEF`: Delete file
* Request sent
```
{
    msg: "DELETEF",
    objContents: [
        "remotePath",
        "token",
    ]
}
* Server sends an OK onced `f.delete()` (needs to check if it exists and other stuff)
```
{
    msg: "OK",
    objContents: null
}
```
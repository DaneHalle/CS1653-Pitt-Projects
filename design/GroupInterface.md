# This is the Communication between the Group Server and Group Client

## `GET`: Client wants a token
Request:
```
{
    msg: "GET",
    objContents: [
        "username"
    ]
}
```
Response Fails:
```
{
    msg: "FAIL",
    objContents: [
        null
    ]
}
```
Response Passes:
```
{
    msg: "OK",
    objContents: [
        "token" // TODO: createToken()
    ]
}
```

## `CUSER`: Create a user
Request:
```
{
    msg: "CUSER",
    objContents: [
        "username",
        "token"
    ]
}
```
Response:
* Fails: When (objContents < 2) or (objContents.get(0) == null or objContents.get(1) == null)
```
{
    msg: "FAIL",
    objContents: null
}
```
* Successful response :: Calss `createUser`
```
{
    msg: "OK",
    objContents: null
}
```

## DUSER: Client wants to delete a user
Request:
```
{
    msg: "DUSER",
    objContents: [
        "username",
        "token"
    ]
}
```
Response:
* Fails: When (objContents < 2) or (objContents.get(0) == null or objContents.get(1) == null)
```
{
    msg: "FAIL",
    objContents: null
}
```
* Successful response :: Calls `deleteUser`
```
{
    msg: "OK",
    objContents: null
}
```

## Client

### Connect
* prints
* TODO: Implement

### isConnect
* A heartbeet for connection

### disconnect
* Sends
```
{
    msg: "Disconnect",
    objContent: null
}
```
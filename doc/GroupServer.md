# Group Server Documentation

## Start

### Runtime Hook
* For when the server is shutdown / killed on runtime it will:
 * Print "Shutting down server!"
 * Create output stream to write the `Userlist.bin`

### Create Group Server Connections
* Reads the userFile `Userlist.bin` into a `UserList`
* If `UserList.bin` does not exist then create a new file and with the user being added to the `'ADMIN'` group and owning the `'ADMIN'` group
* Create a Daemon that automatically saves every 5 minutes
* Create connection with ServerSocket on the port
* Continue with the EchoServer's accept and thread functionality

*Note:* The list of users looks finished however the list of groups does not.

## GroupThread
* Takes the socket and the GroupServer it is running on

### Run
* Envolope for the command the user can send see GroupInterface.md

#### Create Token
* First checks the username :: `checkUser`
* `null` if check does not pass
* Create a new Token with this data:
 - Name of group server (`my_gs.name`)
 - username (from request)
 - UserGroups (@return `synchronized ArrayList<String>`)

#### Create User
* requester == `Token.getSubject` :: TODO
* requester (NOT username) is used for `checkUser`
* Check if the user is `ADMIN` from `getUserGroups`
* Check if user exists already (using `checkUser`)

#### Delete User
* requester == `Token.getSubject` :: TODO
* requester (NOT username) is used for `checkUser`
* Check if the user is `ADMIN` from `getUserGroups`
* Check if user exists already (using `checkUser`)
* Get the list of groups the deleted user belongs to :: `getUserGroups`
* Delete the user from each group in step above :: `removeMember`
* Get the list of ownerships the deleted user belongs to :: `getUserOwnership`
* Delete the user from each ownership in step above :: `deleteOwnedGroup`
* DELETE the user :: `deleteUser`


## UserList Class
* Hashtable of string to User class

### User Class
* Groups: Shared files they do not own
* Ownership: The files they own (may be wrong)

## Envolope
* msg: The message 
* objContents: ArrayList of useful propreties
* Ex:
```
{
    msg: "FAIL",
    objContents: [
        "username",
        "token",
    ]
}
```
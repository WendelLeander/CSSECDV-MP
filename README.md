# SECURITY Svcs (CSSECDV Machine Project)

A Java Swing application with a SQLite database, secured for the CSSECDV machine project.

## Requirements

- JDK 8 or newer
- NetBeans (only for the NetBeans option)

No other installation is needed. The SQLite driver (`sqlite-jdbc-3.23.1.jar`) is included.

## Run with NetBeans

1. Open NetBeans and choose **File > Open Project**.
2. Select the `CSSECDV MP` folder.
3. If NetBeans reports a missing library, right-click **Libraries > Add JAR/Folder** and pick `sqlite-jdbc-3.23.1.jar` from the project folder.
4. Choose **Run > Clean and Build Project** (Shift+F11).
5. Choose **Run > Run Project** (F6). The Login page appears.

Clean and Build also creates the `dist` folder used by the next option.

## Run with Java

1. Open a terminal in the `dist` folder.
2. Run:

   ```
   java -jar CSSECDV.jar
   ```

The `dist` folder must contain `CSSECDV.jar`, `lib/sqlite-jdbc-3.23.1.jar` and `database.db`. Start the program from inside that folder, because it looks for `database.db` in the folder it is started from.

## Accounts

The database has six demo accounts: `admin`, `admin2`, `manager`, `staff`, `client1` and `client2`. Their passwords are listed in the Test Cases document. New accounts can be created from the Register page and receive the Client role.

## Reset the database

`database.demo.db` is a clean copy of the database. To go back to it:

1. Close the application.
2. Copy `database.demo.db` over `database.db` (in the project folder for NetBeans, or in `dist` for the JAR).

On Windows, from the project folder:

```
copy /Y database.demo.db database.db
```

# SQL injection UNION attacks

>   Source: [PortSwigger](https://portswigger.net/web-security/sql-injection/union-attacks)

The `UNION` keyword can be used to retrieve data from other tables within the database. It lets you execute one or more additional `SELECT` queries and append the results to the original query. For example:

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

This SQL query will return a single result set with two columns, containing values from columns `a` and `b` in `table1` and columns `c` and `d` in `table2`.

For a `UNION` query to work, two key requirements must be met:

-   The individual queries must return the same number of columns.
-   The data types in each column must be compatible between the individual queries.

## Determining the number of columns required in an SQL injection UNION attack

>   The first method involves injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs. For example, assuming the injection point is a quoted string within the `WHERE` clause of the original query, you would submit:
>
>   ```sql
>   ' ORDER BY 1-- ' ORDER BY 2-- ' ORDER BY 3-- etc.
>   ```
>
>   This series of payloads modifies the original query to order the results by different columns in the result set. The column in an `ORDER BY` clause can be specified by its index, so you don't need to know the names of any columns. When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as:
>
>   ```
>   The ORDER BY position number 3 is out of range of the number of items in the select list.
>   ```
>
>   The application might actually return the database error in its HTTP response, or it might return a generic error, or simply return no results. Provided you can detect some difference in the application's response, you can infer how many columns are being returned from the query.
>
>   The second method involves submitting a series of `UNION SELECT` payloads specifying a different number of null values:
>
>   ```sql
>   ' UNION SELECT NULL-- ' UNION SELECT NULL,NULL-- ' UNION SELECT NULL,NULL,NULL-- etc.
>   ```
>
>   If the number of nulls does not match the number of columns, the database returns an error, such as:
>
>   ```
>   All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
>   ```
>
>   Note: The reason for using `NULL` as the values returned from the injected `SELECT` query is that the data types in each column must be compatible between the original and the injected queries. Since `NULL` is convertible to every commonly used data type, using `NULL` maximizes the chance that the payload will succeed when the column count is correct.

## Finding columns with a useful data type in an SQL injection UNION attack

>   The reason for performing an SQL injection UNION attack is to be able to retrieve the results from an injected query. Generally, the interesting data that you want to retrieve will be in string form, so you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.
>
>   Having already determined the number of required columns, you can probe each column to test whether it can hold string data by submitting a series of `UNION SELECT` payloads that place a string value into each column in turn. For example, if the query returns four columns, you would submit:
>
>   ```
>   ' UNION SELECT 'a',NULL,NULL,NULL-- ' UNION SELECT NULL,'a',NULL,NULL-- ' UNION SELECT NULL,NULL,'a',NULL-- ' UNION SELECT NULL,NULL,NULL,'a'--
>   ```
>
>   If the data type of a column is not compatible with string data, the injected query will cause a database error, such as:
>
>   ```
>   Conversion failed when converting the varchar value 'a' to data type int.
>   ```
>
>   If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.

## Using an SQL injection UNION attack to retrieve interesting data

>   When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.
>
>   Suppose that:
>
>   -   The original query returns two columns, both of which can hold string data.
>   -   The injection point is a quoted string within the `WHERE` clause.
>   -   The database contains a table called `users` with the columns `username` and `password`.
>
>   In this situation, you can retrieve the contents of the `users` table by submitting the input:
>
>   ```sql
>   ' UNION SELECT username, password FROM users--
>   ```
>
>   Of course, the crucial information needed to perform this attack is that there is a table called `users` with two columns called `username` and `password`. Without this information, you would be left trying to guess the names of tables and columns. In fact, all modern databases provide ways of examining the database structure, to determine what tables and columns it contains.

## Retrieving multiple values within a single column

>   You can easily retrieve multiple values together within this single column by concatenating the values together, ideally including a suitable separator to let you distinguish the combined values. For example, on Oracle you could submit the input:
>
>   ```sql
>   ' UNION SELECT username || '~' || password FROM users--
>   ```
>
>   This uses the double-pipe sequence `||` which is a string concatenation operator on Oracle. The injected query concatenates together the values of the `username` and `password` fields, separated by the `~` character.
>
>   The results from the query will let you read all of the usernames and passwords, for example:
>
>   ```
>   ... administrator~s3cure wiener~peter carlos~montoya ...
>   ```

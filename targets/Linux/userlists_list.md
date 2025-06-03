| Username   | Password     | SSH | FTP | SMB | MySQL        | Privileges        |
|------------|--------------|-----|-----|-----|--------------|-------------------|
| root       | password123  | ✓   | ✗   | ✗   | ✓ (remote)   | System            |
| admin      | admin        | ✓   | ✓   | ✓   | ✓            | Local admin       |
| testuser   | test123      | ✓   | ✓   | ✓   | ✗            | Standard user     |
| guest      | guest        | ✓   | ✓   | ✓   | ✓ (read-only)| Guest access      |
| wpuser     | wppass       | ✗   | ✗   | ✗   | ✓            | WordPress DB      |
| anonymous  | (blank)      | ✗   | ✓   | ✗   | ✗            | FTP only          |
| (empty)    | (blank)      | ✗   | ✗   | ✗   | ✓            | MySQL testdb      |


# owner-lookup.py: who owns this?

A finding action that says who owns the objects a finding is about, from a
CSV file of owners. It returns a message, sends nothing anywhere and
changes nothing, so a dry run does the same as a run.

It offers one action, **Find the owners** (`lookup`), with one input,
**Look up**: **Affected objects** (the default), or **Affected objects and
the path**, which adds every object on the finding's attack path. It needs
Python 3.9 or later, and nothing outside the standard library.

## The owners file

A CSV with a header and three columns. The first row whose `match` fits an
object's name, in any case, names its owner. In `match`, `*` stands for
anything.

```text
match,owner,contact
SVC-*@SCALE.LOCAL,Service accounts team,svc-owners@scale.example
*ADMINS@SCALE.LOCAL,Identity team,identity@scale.example
*.SCALE.LOCAL,Server team,servers@scale.example
```

The message names each object's owner, then the objects with no owner on
file:

```text
SVC-00000@SCALE.LOCAL: Service accounts team (svc-owners@scale.example)
No owner on file: HELPDESK@SCALE.LOCAL
```

## Settings

| Setting | Meaning |
|---|---|
| `owners_file` | The CSV's full path. Default: `owners.example.csv` beside the script, made for the demo. |

## Set it up

1. Copy `owner-lookup.py`, `pathwarden_action.py` and your owners CSV to
   `C:\Pathwarden\actions`.
2. Check it. Give python.exe's full path unless Python is installed for
   all users:

   ```powershell
   pathwarden action check "C:\Program Files\Python313\python.exe" --setting owners_file=C:\Pathwarden\actions\owners.csv -- C:\Pathwarden\actions\owner-lookup.py
   ```

3. Add it:

   ```powershell
   pathwarden action add --name owners --setting owners_file=C:\Pathwarden\actions\owners.csv -- "C:\Program Files\Python313\python.exe" C:\Pathwarden\actions\owner-lookup.py
   pathwarden action run PW-006-1bbba15126c6fc31 --action owners --input scope="Affected objects and the path"
   ```

   ```toml
   [[action]]
   name = "owners"
   command = ["C:\\Program Files\\Python313\\python.exe", "C:\\Pathwarden\\actions\\owner-lookup.py"]
   owners_file = "C:\\Pathwarden\\actions\\owners.csv"
   ```

The same shape fits a lookup in a CMDB or an HR system: read, then answer
in the message. When it calls another system, say so in `sends`.

More: [Writing an action](../../docs/actions.md#an-owner-lookup-that-shows-a-message).

# Custom rule example

This fictional example demonstrates the collection and configuration process.

```powershell
$Path = 'C:\Program Files\Example Organization\Agent\ExampleAgent.exe'

$Publisher = (Get-AppLockerFileInformation -Path $Path).Publisher
$Publisher | Format-List PublisherName, ProductName, BinaryName, BinaryVersion
```

Example output:

```text
PublisherName : O=EXAMPLE ORGANIZATION, L=EXAMPLE CITY, C=US
ProductName   : EXAMPLE SOFTWARE AGENT
BinaryName    : EXAMPLEAGENT.EXE
BinaryVersion : 1.0.0.0
```

Configure one custom slot:

```text
Name            = Example Software Agent
Publisher       = O=EXAMPLE ORGANIZATION, L=EXAMPLE CITY, C=US
Product name    = EXAMPLE SOFTWARE AGENT
Executable      = EXAMPLEAGENT.EXE
Minimum version = 1.0.0.0
```

Review the executable's security boundary before enabling the slot. This example is fictional and must not be copied as a real publisher rule.

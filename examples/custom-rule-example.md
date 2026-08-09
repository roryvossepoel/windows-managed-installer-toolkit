# Custom rule example

This fictional example demonstrates the collection and configuration process.

```powershell
$Path = 'C:\Program Files\Contoso\Agent\ContosoAgent.exe'

$Publisher = (Get-AppLockerFileInformation -Path $Path).Publisher
$Publisher | Format-List PublisherName, ProductName, BinaryName, BinaryVersion
```

Example output:

```text
PublisherName : O=CONTOSO B.V., L=HEERLEN, C=NL
ProductName   : CONTOSO SOFTWARE AGENT
BinaryName    : CONTOSOAGENT.EXE
BinaryVersion : 1.0.0.0
```

Configure one custom slot:

```text
Name            = Contoso Software Agent
Publisher       = O=CONTOSO B.V., L=HEERLEN, C=NL
Product name    = CONTOSO SOFTWARE AGENT
Executable      = CONTOSOAGENT.EXE
Minimum version = 1.0.0.0
```

Review the executable's security boundary before enabling the slot. This example is fictional and must not be copied as a real publisher rule.

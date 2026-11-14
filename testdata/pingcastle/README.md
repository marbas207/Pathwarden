# PingCastle report fixtures

Hand-written health-check reports in the format PingCastle writes
(`ad_hc_<domain>.xml`: .NET `XmlSerializer` output of the `HealthcheckData`
class in `PingCastleCommon/Data/HealthcheckData.cs`,
<https://github.com/netwrix/pingcastle>). They hold the elements Pathwarden
reads plus a few neighbours, for domain `contoso.local` of the
`testdata/forest` collection. They are not real PingCastle output, and no
PingCastle code or text is copied here (the rule IDs and rationales mirror
PingCastle's rule names so the fixture looks like a real report).

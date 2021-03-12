// From https://github.com/fireeye/red_team_tool_countermeasures/blob/3a773645093e77107dfc4e3b29eb74845cc2f25d/rules/RUBEUS/production/yara/HackTool_MSIL_Rubeus_1.yar
// License: BSD 2-clause
rule HackTool_MSIL_Rubeus_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public Rubeus project."
        md5 = "66e0681a500c726ed52e5ea9423d2654"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}
<#
.SYNOPSIS
Check and set security best practice registry settings for Adobe Acrobat/Reader DC

.EXAMPLE
.\AdobeDC.ps1
Checks and sets the registry settings.

.NOTES
Uses registry functions from Carbon project: https://github.com/webmd-health-services/Carbon/
#>

#BEGIN: Registry settings that will be checked and set
$Settings = @(
    @{
        Ensure = 'Present'
        Hive = 'HKLM:'
        Key = '\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'
        ValueName = 'bDisableJavaScript'
        ValueData = 1
        ValueType = 'REG_DWORD'
    },
    @{
        Ensure = 'Present'
        Hive = 'HKLM:'
        Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'
        ValueName = 'bEnableFlash'
        ValueData = 0
        ValueType = 'REG_DWORD'
    },
    @{
        Ensure = 'Present'
        Hive = 'HKLM:'
        Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'
        ValueName = 'bDisableJavaScript'
        ValueData = 1
        ValueType = 'REG_DWORD'
    }
)
#END: Registry settings that will be checked and set

#BEGIN: Helper functions used by the script
function Install-CRegistryKey
{
    <#
    .SYNOPSIS
    Creates a registry key.  If it already exists, does nothing.
    
    .DESCRIPTION
    Given the path to a registry key, creates the key and all its parents.  If the key already exists, nothing happens.
    
    .EXAMPLE
    Install-CRegistryKey -Path 'hklm:\Software\Carbon\Test'
    
    Creates the `hklm:\Software\Carbon\Temp` registry key if it doesn't already exist.
    #>
    [CmdletBinding(SupportsShouldPRocess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key to create.
        $Path
    )

    if( -not (Test-Path -Path $Path -PathType Container) )
    {
        New-Item -Path $Path -ItemType RegistryKey -Force | Out-String | Write-Verbose
    }
}
function Remove-CRegistryKeyValue
{
    <#
    .SYNOPSIS
    Removes a value from a registry key, if it exists.
    
    .DESCRIPTION
    If the given key doesn't exist, nothing happens.
    
    .EXAMPLE
    Remove-CRegistryKeyValue -Path hklm:\Software\Carbon\Test -Name 'InstallPath'
    
    Removes the `InstallPath` value from the `hklm:\Software\Carbon\Test` registry key.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key where the value should be removed.
        $Path,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the value to remove.
        $Name
    )

    if( (Test-CRegistryKeyValue -Path $Path -Name $Name) )
    {
        if( $pscmdlet.ShouldProcess( ('Item: {0} Property: {1}' -f $Path,$Name), 'Remove Property' ) )
        {
            Remove-ItemProperty -Path $Path -Name $Name
        }
    }
}
function Set-CRegistryKeyValue
{
    <#
    .SYNOPSIS
    Sets a value in a registry key.
    
    .DESCRIPTION
    The `Set-CRegistryKeyValue` function sets the value of a registry key. If the key doesn't exist, it is created first. Uses PowerShell's `New-ItemPropery` to create the value if doesn't exist. Otherwise uses `Set-ItemProperty` to set the value.

    `DWord` and `QWord` values are stored in the registry as unsigned integers. If you pass a negative integer for the `DWord` and `QWord` parameters, PowerShell will convert it to an unsigned integer before storing. You won't get the same negative number back.

    To store integer values greater than `[Int32]::MaxValue` or `[Int64]::MaxValue`, use the `UDWord` and `UQWord` parameters, respectively, which are unsigned integers. These parameters were in Carbon 2.0.

    In versions of Carbon before 2.0, you'll need to convert these large unsigned integers into signed integers. You can't do this with casting. Casting preservers the value, not the bits underneath. You need to re-interpret the bits. Here's some sample code:

        # Carbon 1.0
        $bytes = [BitConverter]::GetBytes( $unsignedInt )
        $signedInt = [BitConverter]::ToInt32( $bytes, 0 )  # Or use `ToInt64` if you're working with 64-bit/QWord values
        Set-CRegistryKeyValue -Path $Path -Name 'MyUnsignedDWord' -DWord $signedInt

        # Carbon 2.0
        Set-CRegistryKeyValue -Path $Path -Name 'MyUnsignedDWord' -UDWord $unsignedInt
    
    .LINK
    Get-CRegistryKeyValue
    
    .LINK
    Test-CRegistryKeyValue
    
    .EXAMPLE
    Set-CRegistryKeyValue -Path 'hklm:\Software\Carbon\Test -Name Status -String foobar 
    
    Creates the `Status` string value under the `hklm:\Software\Carbon\Test` key and sets its value to `foobar`.
    
    .EXAMPLE
    Set-CRegistryKeyValue -Path 'hklm:\Software\Carbon\Test -Name ComputerName -String '%ComputerName%' -Expand
    
    Creates an expandable string.  When retrieving this value, environment variables will be expanded.
    
    .EXAMPLE
    Set-CRegistryKeyValue -Path 'hklm:\Software\Carbon\Test -Name Movies -String ('Signs','Star Wars','Raiders of the Lost Ark')
    
    Sets a multi-string (i.e. array) value.
    
    .EXAMPLE
    Set-CRegistryKeyValue -Path hklm:\Software\Carbon\Test -Name 'SomeBytes' -Binary ([byte[]]@( 1, 2, 3, 4)) 
    
    Sets a binary value (i.e. `REG_BINARY`).
    
    .EXAMPLE
    Set-CRegistryKeyValue -Path hklm:\Software\Carbon\Test -Name 'AnInt' -DWord 48043
    
    Sets a binary value (i.e. `REG_DWORD`).
    
    .EXAMPLE
    Set-CRegistryKeyValue -Path hklm:\Software\Carbon\Test -Name 'AnInt64' -QWord 9223372036854775807
    
    Sets a binary value (i.e. `REG_QWORD`).
    
    .EXAMPLE
    Set-CRegistryKeyValue -Path hklm:\Software\Carbon\Test -Name 'AnUnsignedInt' -UDWord [uint32]::MaxValue
    
    Demonstrates how to set a registry value with an unsigned integer or an integer bigger than `[int]::MaxValue`.

    The `UDWord` parameter was added in Carbon 2.0. In earlier versions of Carbon, you have to convert the unsigned int's bits to a signed integer:

        $bytes = [BitConverter]::GetBytes( $unsignedInt )
        $signedInt = [BitConverter]::ToInt32( $bytes, 0 )
        Set-CRegistryKeyValue -Path $Path -Name 'MyUnsignedDWord' -DWord $signedInt
        
    .EXAMPLE
    Set-CRegistryKeyValue -Path hklm:\Software\Carbon\Test -Name 'AnUnsignedInt64' -UQWord [uint64]::MaxValue
    
    Demonstrates how to set a registry value with an unsigned 64-bit integer or a 64-bit integer bigger than `[long]::MaxValue`.

    The `UQWord parameter was added in Carbon 2.0. In earlier versions of Carbon, you have to convert the unsigned int's bits to a signed integer:

        $bytes = [BitConverter]::GetBytes( $unsignedInt )
        $signedInt = [BitConverter]::ToInt64( $bytes, 0 )
        Set-CRegistryKeyValue -Path $Path -Name 'MyUnsignedDWord' -DWord $signedInt
    
    .EXAMPLE
    Set-CRegistryKeyValue -Path hklm:\Software\Carbon\Test -Name 'UsedToBeAStringNowShouldBeDWord' -DWord 1 -Force
    
    Uses the `Force` parameter to delete the existing `UsedToBeAStringNowShouldBeDWord` before re-creating it.  This flag is useful if you need to change the type of a registry value.
    #>
    [CmdletBinding(SupportsShouldPRocess=$true,DefaultParameterSetName='String')]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key where the value should be set.  Will be created if it doesn't exist.
        $Path,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the value being set.
        $Name,
        
        [Parameter(Mandatory=$true,ParameterSetName='String')]
        [AllowEmptyString()]
        [AllowNull()]
        [string]
        # The value's data.  Creates a value for holding string data (i.e. `REG_SZ`). If `$null`, the value will be saved as an empty string.
        $String,
        
        [Parameter(ParameterSetName='String')]
        [Switch]
        # The string should be expanded when retrieved.  Creates a value for holding expanded string data (i.e. `REG_EXPAND_SZ`).
        $Expand,
        
        [Parameter(Mandatory=$true,ParameterSetName='Binary')]
        [byte[]]
        # The value's data.  Creates a value for holding binary data (i.e. `REG_BINARY`).
        $Binary,
        
        [Parameter(Mandatory=$true,ParameterSetName='DWord')]
        [int]
        # The value's data.  Creates a value for holding a 32-bit integer (i.e. `REG_DWORD`).
        $DWord,
        
        [Parameter(Mandatory=$true,ParameterSetName='DWordAsUnsignedInt')]
        [uint32]
        # The value's data as an unsigned integer (i.e. `UInt32`).  Creates a value for holding a 32-bit integer (i.e. `REG_DWORD`).
        $UDWord,
        
        [Parameter(Mandatory=$true,ParameterSetName='QWord')]
        [long]
        # The value's data.  Creates a value for holding a 64-bit integer (i.e. `REG_QWORD`).
        $QWord,
        
        [Parameter(Mandatory=$true,ParameterSetName='QWordAsUnsignedInt')]
        [uint64]
        # The value's data as an unsigned long (i.e. `UInt64`).  Creates a value for holding a 64-bit integer (i.e. `REG_QWORD`).
        $UQWord,
        
        [Parameter(Mandatory=$true,ParameterSetName='MultiString')]
        [string[]]
        # The value's data.  Creates a value for holding an array of strings (i.e. `REG_MULTI_SZ`).
        $Strings,
        
        [Switch]
        # Removes and re-creates the value.  Useful for changing a value's type.
        $Force,
        
        [Parameter(DontShow=$true)]
        [Switch]
        # OBSOLETE. Will be removed in a future version of Carbon.
        $Quiet
    )

    if( $PSBoundParameters.ContainsKey('Quiet') )
    {
        Write-Warning ('Set-CRegistryKeyValue''s -Quiet switch is obsolete and will be removed in a future version of Carbon. Please remove usages.')
    }

    $value = $null
    $type = $pscmdlet.ParameterSetName
    switch -Exact ( $pscmdlet.ParameterSetName )
    {
        'String' 
        { 
            $value = $String 
            if( $Expand )
            {
                $type = 'ExpandString'
            }
        }
        'Binary' { $value = $Binary }
        'DWord' { $value = $DWord }
        'QWord' { $value = $QWord }
        'DWordAsUnsignedInt' 
        { 
            $value = $UDWord 
            $type = 'DWord'
        }
        'QWordAsUnsignedInt' 
        { 
            $value = $UQWord 
            $type = 'QWord'
        }
        'MultiString' { $value = $Strings }
    }
    
    Install-CRegistryKey -Path $Path
    
    if( $Force )
    {
        Remove-CRegistryKeyValue -Path $Path -Name $Name
    }

    if( Test-CRegistryKeyValue -Path $Path -Name $Name )
    {
        $currentValue = Get-CRegistryKeyValue -Path $Path -Name $Name
        if( $currentValue -ne $value )
        {
            Write-Verbose -Message ("[{0}@{1}] {2} -> {3}'" -f $Path,$Name,$currentValue,$value)
            Set-ItemProperty -Path $Path -Name $Name -Value $value
        }
    }
    else
    {
        Write-Verbose -Message ("[{0}@{1}]  -> {2}'" -f $Path,$Name,$value)
        $null = New-ItemProperty -Path $Path -Name $Name -Value $value -PropertyType $type
    }
}
function Test-CRegistryKeyValue
{
    <#
    .SYNOPSIS
    Tests if a registry value exists.
    
    .DESCRIPTION
    The usual ways for checking if a registry value exists don't handle when a value simply has an empty or null value.  This function actually checks if a key has a value with a given name.
    
    .EXAMPLE
    Test-CRegistryKeyValue -Path 'hklm:\Software\Carbon\Test' -Name 'Title'
    
    Returns `True` if `hklm:\Software\Carbon\Test` contains a value named 'Title'.  `False` otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key where the value should be set.  Will be created if it doesn't exist.
        $Path,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the value being set.
        $Name
    )

    if( -not (Test-Path -Path $Path -PathType Container) )
    {
        return $false
    }
    
    $properties = Get-ItemProperty -Path $Path 
    if( -not $properties )
    {
        return $false
    }
    
    $member = Get-Member -InputObject $properties -Name $Name
    if( $member )
    {
        return $true
    }
    else
    {
        return $false
    }
}
function Get-CRegistryKeyValue
{
    <#
    .SYNOPSIS
    Gets the value from a registry key.
    
    .DESCRIPTION
    PowerShell's `Get-ItemProperty` cmdlet is a pain to use.  It doesn't actually return an object representing a registry key's value, but some other weird object that requires painful gyrations to get values from. This function returns just the value of a key.
    
    .EXAMPLE
    Get-CRegistryKeyValue -Path 'hklm:\Software\Carbon\Test' -Name 'Title'
    
    Returns the value of the 'hklm:\Software\Carbon\Test' key's `Title` value.  
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key where the value should be set.  Will be created if it doesn't exist.
        $Path,
        
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the value being set.
        $Name
    )
    
    if( -not (Test-CRegistryKeyValue -Path $Path -Name $Name) )
    {
        return $null
    }
    
    $itemProperties = Get-ItemProperty -Path $Path -Name *
    $value = $itemProperties.$Name
    Write-Debug -Message ('[{0}@{1}: {2} -is {3}' -f $Path,$Name,$value,$value.GetType())
    return $value
}
#END: helper functions

#BEGIN: executing the script
try {
    foreach ($Setting in $Settings) {
        if ($Setting.Ensure -eq 'Present') {
            switch ($Setting.ValueType) {
                'REG_SZ' { Set-CRegistryKeyValue -Path ($Setting.Hive + $Setting.Key) -Name $Setting.ValueName -String $Setting.ValueData }
                'REG_BINARY' { Set-CRegistryKeyValue -Path ($Setting.Hive + $Setting.Key) -Name $Setting.ValueName -Binary $Setting.ValueData }
                'REG_DWORD' { Set-CRegistryKeyValue -Path ($Setting.Hive + $Setting.Key) -Name $Setting.ValueName -DWord $Setting.ValueData }
                'REG_QWORD' { Set-CRegistryKeyValue -Path ($Setting.Hive + $Setting.Key) -Name $Setting.ValueName -QWord $Setting.ValueData }
                'REG_MULTI_SZ' { Set-CRegistryKeyValue -Path ($Setting.Hive + $Setting.Key) -Name $Setting.ValueName -Strings $Setting.ValueData }
                'REG_EXPAND_SZ' { Set-CRegistryKeyValue -Path ($Setting.Hive + $Setting.Key) -Name $Setting.ValueName -Expand $Setting.ValueData }
            }
        } elseif ($Setting.Ensure -eq 'Absent') {
            Remove-CRegistryKeyValue -Path ($Setting.Hive + $Setting.Key) -Name $Setting.ValueName
        }
    }
} catch {

}
#END: executing the script
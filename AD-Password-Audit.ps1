#################################################################
#####  Must be executed from a Domain Admin account         #####
#################################################################

Clear-Host

#Start-Transcript -Path "$env:USERPROFILE\Desktop\PassTester_log.txt" -Append | Out-Null
Start-Transcript -Path "C:\Temp\PassTester_log.txt" -Append | Out-Null

if(Get-Module WriteAscii)
    {
        Import-Module WriteAscii
    }
    else
    {
        Install-Module -Name WriteAscii
    }

Write-Ascii -InputObject 'DM - Password Audit'
Write-Host "`n"

if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "Must be opened from a Domain Admin account !"
    Stop-Transcript | Out-Null
    Start-Sleep 5
    exit
}

function date {
    (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

$directory_audit = "C:\Temp\PassTester"
$directory_exports_NTDS = "$directory_audit\NTDS"

function NTDS_copy {
    if(Get-Module DSInternals)
    {
        Import-Module DSInternals
    }
    else
    {
        Install-Module -Name DSInternals
    }

    if (!$(Test-Path $directory_audit))
    {
        Write-Host "$(Get-Date) - Creating directories"
        New-Item -ItemType Directory -Path $directory_audit | Out-Null
    }

    if ($(Get-ChildItem $directory_audit) -ne $null)
    {
        Write-Host "$(Get-Date) - Folder $directory_audit is not empty !" -ForegroundColor Yellow
        Stop-Transcript | Out-Null
        Start-Sleep 5
        exit
    }
    else
    {
        New-Item -ItemType Directory -Path "$directory_audit\results" | Out-Null
        New-Item -ItemType Directory -Path "$directory_exports_NTDS" | Out-Null
    }

    #Copy of the NTDS database
    if ($env:LOGONSERVER.Substring(2) -ne $env:COMPUTERNAME)
    {
        #Creating a temporary share
        New-SmbShare -Path $directory_exports_NTDS -Name "Share_Audit" -FullAccess (Get-LocalGroup -SID "S-1-5-32-544").name

        $Partage = "\\$env:COMPUTERNAME\Share_Audit"
        #Log on to the DC
        $session = New-PSSession -ComputerName $env:LOGONSERVER.Substring(2) -Name Audit
        Write-Host "$(Get-Date) - Extracting NTDS database ..."
        #Remote copy of the NTDS database and transfer to the network share
        Invoke-Command -Session $session -ScriptBlock {
            param($Partage)
            NTDSUTIL "Activate Instance NTDS" "IFM" "Create Full $Partage" "q" "q"
        } -ArgumentList $Partage | Out-Null
        #Closing the network share
        Remove-SmbShare -Name "Share_Audit" -Force > $null
    }
    else
    {
        Write-Host "$(Get-Date) - Extracting NTDS database ..."
        NTDSUTIL "Activate Instance NTDS" "IFM" "Create Full $directory_exports_NTDS" "q" "q"# | Out-Null
    }

    Write-Host "$(Get-Date) - NTDS database decryption"
    #Loading the decryption key
    $Key = Get-BootKey -SystemHiveFilePath "$directory_exports_NTDS\registry\SYSTEM"

    #Decrypting the NTDS database with the SYSTEM key
    Get-ADDBAccount -BootKey $Key -DatabasePath "$directory_exports_NTDS\Active Directory\ntds.dit" -All |`
    Format-Custom -View HashcatNT | Out-File "$directory_audit\Hashdump.txt"

    #Deleting empty lines and krbtgt account and machines acounts
    $NTDS = Get-Content "$directory_audit\Hashdump.txt"
    $NTDS | Where-Object { $_ -ne '' -and $_ -notmatch "krbtgt" -and $_ -notmatch "\$" } | Get-Random -Count $NTDS.Count | Set-Content "$directory_audit\Hashdump_cleared.txt"
    
    Write-Host "$(Get-Date) - Extract Done !"
}

function Password_Control {
    if (!$(Test-Path "$directory_audit\Hashdump_cleared.txt"))
        {
            Write-Host "No file $directory_audit\Hashdump_cleared.txt present !"
            Start-Sleep 10
            Exit
        }
    $NTDS = Get-Content "$directory_audit\Hashdump_cleared.txt"
    $total_users = $NTDS.count
    $compromised_count = 0
    $empty_count = 0
    #Users randomized to avoid to inject Administrator and Guest user in first
    $mixed_users = $NTDS | Get-Random -Count $NTDS.Count
    $compromised_users = @()

    Write-Host "$(Get-Date) - Password control ..."

    ###### Tests HashNTLM #####

    # Display the progress bar
    $progressParams = @{
        Activity = "Processing in progress"
        Status   = "Loading ..."
        PercentComplete = 0
    }
    Write-Progress @progressParams
    $totalUsers = $NTDS.Count
    $i = 0

    # Control task
    foreach($user_key in $mixed_users)
    {   
        # Update the progress bar
        $progressParams.PercentComplete = ($i++ / $totalUsers) * 100
        $progressParams.Status = "$i / $totalUsers users"
        Write-Progress @progressParams

        if ($request.Headers.'X-RateLimit-Remaining' -eq "25")
        {
            Write-Host "Reached the limit of the API... relax for about..." -ForegroundColor Red
            #Write-Host "X-RateLimit-Reset:" $request.Headers.'X-RateLimit-Reset'
            $WaitTime = [Int][String]$request.Headers.'X-RateLimit-Reset' + 60
            Write-Host "Wait Time:" $WaitTime "seconds" -ForegroundColor Red
            Start-Sleep $WaitTime
        }

        $user = $user_key.split(":")[0]
        $hash = $user_key.split(":")[1]

        if($hash -like "31d6cfe0d16ae931b73c59d7e0c089c0" -or $hash -eq $null)
        {
            $user | Out-File "$directory_audit\results\Empty_users.txt" -Append
            Write-Host "[*]" -ForegroundColor Yellow -NoNewline; Write-Host " User's password " -NoNewline ; Write-Host "$user" -ForegroundColor Yellow -NoNewline; Write-Host " empty !"
            $empty_count ++
            continue
        }

        try {
            $request = Invoke-WebRequest https://ntlm.pw/api/lookup/nt/$hash
            #$request = Invoke-WebRequest "https://ntlm.pw/$hash" -UseBasicParsing | Select-Object StatusCode
            #$Password = Invoke-WebRequest https://ntlm.pw/$hash | Select-Object -Expand Content
        }
        catch {
            $request = $_.Exception
        }
        
        if ($request.StatusCode -eq "200")
        {
            $user + ":" + $request.Content | Out-File "$directory_audit\results\Compromised_users.txt" -Append -NoNewline
            $compromised_users += $user
            Write-Host "[+]" -ForegroundColor Green -NoNewline; Write-Host " User's password " -NoNewline ; Write-Host "$user" -ForegroundColor Green -NoNewline; Write-Host " vulnerable !"
            #Write-Host "Username:" $user "- Status Code:" $request.StatusCode "- Password:" $request.Content "- Rate Limit: " $request.Headers.'X-RateLimit-Remaining'
            $compromised_count ++ 
            #$request.content
        }
        elseif ($request.StatusCode -eq "429")
        {
            Write-Host "Too much request"
            Write-Host "Stopped at user : $user" -ForegroundColor Red
            #Write-Host "Username:" $user "- Status Code:" $request.StatusCode "- Password:" $request.Content "- Rate Limit: " $request.Headers.'X-RateLimit-Remaining'
            Start-Sleep 600
        }
        elseif ($request.StatusCode -eq "204")
        {
            #Write-Host "Username:" $user "- Status Code:" $request.StatusCode "- Password:" $request.Content "- Rate Limit: " $request.Headers.'X-RateLimit-Remaining'
        }
    }

    Write-Host "`n$(Get-Date) - Extract finished !"
    Write-Host "`n$i/$total_users users have been tested :"
    Write-Host "$empty_count empty passwords" -ForegroundColor Yellow
    Write-Host "$compromised_count compromised passwords" -ForegroundColor green
    Write-Host "Results available at $directory_audit\results\"
    Stop-Transcript | Out-Null
    Start-Sleep 60
}

function PasswordReset {
    foreach ($user in $compromised_users)
    {
        Set-ADUser -Identity $user -ChangePasswordAtLogon $true
    }
}

# TO DO
# Create ticket to change password

Write-Host "Menu :"
Write-Host "1 - Only extract NTDS database"
Write-Host "2 - Only Audit NTLM hashes from a previous extract"
Write-Host "3 - Extract and Audit NTLM hashes"
Write-Host "4 - Extract / Audit NTLM hashes and Request Password Reset"
Write-Host "5 - Exit"

$choice = Read-Host "Select an option"

Switch ($choice){
    "1" {NTDS_copy; Stop-Transcript | Out-Null}
    "2" {Password_Control}
    "3" {NTDS_copy; Password_Control}
    "4" {NTDS_copy; Password_Control; PasswordReset}
    "5" {exit}
    "Default" {Write-Host "Invalid choice. Please choose a valid option."}
}


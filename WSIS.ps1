# Name        : Windows Sensitive Information Searcher
# Author      : Greg Nimmo
# Version     : 1.1
# Description : Post exploitation script to search a specified shared folder for sensitive information
#               The script take multiple options, including the file types to search and
#               the content to identify, based on an array of keywords  
#               If alternative connection / credentials are not supplied the current user, domain 
#               controller and sysvol share details will be utilised

# function for displaying the main menu
function Show-Menu {
    param (
        [string]$title = 'Windows Sensitive Information Searcher'
    )
    Write-Host "`n============= $title =============="
    Write-Host "`t 'A' Create file extension list"
    Write-Host "`t 'B' Create keyword search list "
    Write-Host "`t 'C' Configure connection settings"
    Write-Host "`t 'D' Execute search"
    Write-Host "`t 'Q to Quit'"
    Write-Host "========================================================"
}

# main program body
do {
    Show-Menu
    $choice = Read-Host "`tEnter your selection"
    
    switch ($choice) {
    'A'{
        # create an array to hold a list of file extensions
        # array to be used during the search process
        $fileExtensionArray = @()
        Write-Host "`nCreate file extension search list"
        do {
            $fileExtension = (Read-Host "Enter a file extensions to search (pres [ENTER] to stop) ")
            if ($fileExtension -eq ''){
                break
            }
            elseif ($fileExtension -ne '') {
                $fileExtensionArray += '*.' + $fileExtension
            }
        }
        until ($fileExtension -eq '')
        Write-Host "`n`t File types :"  $fileExtensionArray

    } # end switch A

    'B'{
        # create an array of keywords to search for within files identified by the extension array
        $keywordSearchArray = @()
        Write-Host "`nCreate keyword search list"
        do {
            $keyword = (Read-Host "Enter a keyword (pres [ENTER] to stop) ")
            if ($keyword -eq ''){
                break
            }
            elseif ($keyword -ne '') {
                $keywordSearchArray += $keyword
            }
        }
        until ($keyword -eq '')
        Write-Host "`n`t Keywords :" $keywordSearchArray
    } # end switch B
    
    'C'{
    # set config to current user and domain if not specified by user
    Write-Host "`nConfigure connection settings"
    # set server details
    $server = Read-Host 'Enter a server name (blank to use current logon server)'
    if ($server -eq ''){
        $server = $env:LOGONSERVER
    }
    else{
        $server = "\\$server"
    }
   
    # set share details
    $share = Read-Host 'Enter server share (blank to use SYSVOL)'
    if ($share -eq ''){
        $share = "\SYSVOL"
    }
    else{
        $share = "\$share"
    }
    
    # set alternative authentication 
    do{
        $choice = @('Y','N')
        $auth = Read-Host 'Enter alternate credentials (Y/N)'
        if ($auth -eq 'N'){
            break
        }
        else{
        Write-Host 'Authentication'
        # gather alternative configuration information
        $domainName = Read-Host 'Enter domain name'
        $userName = Read-Host 'Enter username'
        $password = Read-Host -Prompt "Enter password" -AsSecureString
        $domainAccount = "$domainName\$username"
        $alternativeCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $domainAccount, $password
        }

    }while ($auth -notin $choice)
    # end do
    # output configuration details
    if ($auth -eq 'N'){
        Write-Host "`nConfiguration settings :"
        Write-Host "`tUsing current session defaults"
    }
    else{
        Write-Host "`nConfiguration settings :" 
        write-host "`t Server : $server"
        Write-Host "`t Share : $share"
        write-host "`t Domain : $domainName"
        write-host "`t Username : $userName"
        Write-Host "`t Password : $password"
    }
    } # end switch C

    'D'{
        # identify a free drive letter and map the network share 
        Write-Host "`nExecute search"
        # check what drives are already mapped
        $driveList=(Get-PSDrive -PSProvider filesystem).Name
        Foreach ($driveLetter in "DEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()) {
            If ($driveList -notcontains $driveLetter) {
                # map the drive using current powershell session
                if ($auth -eq 'N'){
                    $mappedDrive=New-PSDrive -PSProvider filesystem -Name $driveLetter -Root $server$share -Persist
                    break
                }
                else{
                    # map drive based on alternative credentials 
                    $mappedDrive=New-PSDrive -PSProvider filesystem -Name $driveLetter -Root $server$share -Credential $alternativeCredentials -Persist
                    break
                }# end else
            } # end if 
        } # end foreach loop
        
        # create a  timestamp
        $timeStamp = Get-Date -Format "dd-MM-yyyy"

        # run a recursive search for specified file types
        $filesFound = @(Get-ChildItem $server$share -Include $fileExtensionArray -Recurse -ErrorAction SilentlyContinue)

        # search each file for specified keywords and save the results
        $filesFound | ForEach-Object {
        $itemOfInterest = $_ | Select-String -Pattern $keywordSearchArray
        if ($itemOfInterest -ne $null){
            $itemOfInterest | Out-File -Append "$($env:USERPROFILE)\Documents\$($env:USERDNSDOMAIN)_Results_$($timeStamp).txt"}
        }

        # remove the mapped drive
        Write-Host 'Removing mapped drive' $mappedDrive
        Remove-PSDrive -PSProvider FileSystem -Name $mappedDrive
    } # end switch D

    'Q'{
        Write-Host "`nExiting program."
        return
    }
    } # end switch Q

} until ($choice -eq 'Q') # end do

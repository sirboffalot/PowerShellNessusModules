<#
.Synopsis
   Gets the SSL ports from a Nessus output file.
.DESCRIPTION
   Takes a Nessus output file (.nessus) and extracts all SSL ports from it in the format host:port. Returns output to the screen.  Idea stolen from a Python script called nessus extract here https://medium.com/@x41x41x41/extracting-ssl-ports-from-nessus-exports-14dc67dd248e.
.EXAMPLE
   Get-NessusSSLPorts -File ./BobMonkhouse-HostScan.nessus
.EXAMPLE
   Get-NessusSSLPorts ./BobMonkhouse-HostScan.nessus | Out-File ./BobMonkhouseSSLPorts.txt
#>
function Get-NessusSSLPorts
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        # File the path to a .nessus file
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $File
    )

    Begin
    {
        # Test that the path is valid, otherwise throw error
        if(-not (Test-Path $File)) { Throw "Filepath is invalid" }

        # Load in the Nessus file as XML
        $nessusXML = [xml](Get-Content $File)

        # Output text
        $outputData = ""
    }
    Process
    {
        # Loop through all the hosts
        foreach($reportHost in $nessusXML.NessusClientData_v2.Report.ReportHost) 
        {
            # Get the name of the host
            $reportHostIP = ($reportHost.HostProperties.ChildNodes | Where-Object { $_.name -eq "host-ip" })."#text"
            
            # Loop through all the issues which have a plugin ID of 10863
            foreach($rptSSLCertInfoIssue in ($reportHost.ReportItem | ? { $_.pluginID -eq "10863" })) 
            {
                # Add the SSL line to the output
                $outputData += $reportHostIP+":"+$rptSSLCertInfoIssue.port+"`r`n"
            }
        }
        
    }
    End
    {
        return $outputData
    }
}
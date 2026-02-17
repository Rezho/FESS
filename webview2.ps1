Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type -Path "C:\WebView2\Microsoft.Web.WebView2.Core.dll"
Add-Type -Path "C:\WebView2\Microsoft.Web.WebView2.WinForms.dll"

$userDataFolder = "C:\WebView2\UserData"
if (-not (Test-Path $userDataFolder)) { New-Item -ItemType Directory -Path $userDataFolder -Force }

# Donner les droits complets sur le dossier
$acl = Get-Acl $userDataFolder
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule)
Set-Acl $userDataFolder $acl

$form = New-Object System.Windows.Forms.Form
$form.Size = New-Object System.Drawing.Size(1280, 800)
$form.StartPosition = "CenterScreen"

$browser = New-Object Microsoft.Web.WebView2.WinForms.WebView2
$browser.CreationProperties = New-Object Microsoft.Web.WebView2.WinForms.CoreWebView2CreationProperties
$browser.CreationProperties.UserDataFolder = $userDataFolder
$browser.Dock = 'Fill'
$form.Controls.Add($browser)

$form.Add_Shown({
    $browser.EnsureCoreWebView2Async($null)

    $browser.Add_CoreWebView2InitializationCompleted({
    param($s, $e)
    if ($e.IsSuccess) {
        Write-Host "OK"

        # Intercepter les clics sur fichiers Office et décoder les accents
        $browser.CoreWebView2.Add_NavigationStarting({
            param($s, $e)
            $decoded = [System.Uri]::UnescapeDataString($e.Uri)
            if ($decoded -match "\.(docx?|xlsx?|pptx?)$") {
                $e.Cancel = $true
                Start-Process $decoded
            }
        })

        $browser.CoreWebView2.Add_NewWindowRequested({
            param($s, $e)
            $decoded = [System.Uri]::UnescapeDataString($e.Uri)
            if ($decoded -match "\.(docx?|xlsx?|pptx?)$") {
                $e.Handled = $true
                Start-Process $decoded
            }
        })

        $browser.CoreWebView2.Navigate("http://fess.contoso.local:8080/")
    } else {
        Write-Host "ERREUR : $($e.InitializationException.Message)"
    }
})
})

[void]$form.ShowDialog()

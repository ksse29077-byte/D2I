param(
    [Parameter(Mandatory = $true)]
    [string]$WindowTitle,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = $WindowTitle
$form.Size = New-Object System.Drawing.Size(420, 180)
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Name = "D2IText"
$textBox.Location = New-Object System.Drawing.Point(24, 28)
$textBox.Size = New-Object System.Drawing.Size(350, 24)
$textBox.Add_TextChanged({
    [System.IO.File]::WriteAllText($OutputPath, $textBox.Text)
})
$form.Controls.Add($textBox)

$form.Add_Shown({
    $form.Activate()
})

[System.Windows.Forms.Application]::Run($form)

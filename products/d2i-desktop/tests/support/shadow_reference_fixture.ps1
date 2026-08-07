param(
    [Parameter(Mandatory = $true)]
    [string]$WindowTitle,

    [Parameter(Mandatory = $true)]
    [ValidateSet('normal', 'already_correct', 'clarification', 'escalation', 'human_error', 'unsupported')]
    [string]$Scenario,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Interactive', 'Instrumented')]
    [string]$ReferenceMode,

    [Parameter(Mandatory = $true)]
    [string]$StatePath,

    [Parameter(Mandatory = $true)]
    [string]$EventPath,

    [Parameter(Mandatory = $true)]
    [string]$ReadyPath,

    [Parameter(Mandatory = $true)]
    [string]$CommandPath,

    [Parameter(Mandatory = $true)]
    [string]$ArmPath,

    [Parameter(Mandatory = $true)]
    [string]$ArmToken
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public sealed class D2IShadowReferenceForm : Form
{
    private const int WsExNoActivate = 0x08000000;
    private const uint SwpNoSize = 0x0001;
    private const uint SwpNoMove = 0x0002;
    private const uint SwpNoActivate = 0x0010;
    private static readonly IntPtr HwndBottom = new IntPtr(1);
    private readonly bool nonActivating;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(
        IntPtr window,
        IntPtr insertAfter,
        int x,
        int y,
        int width,
        int height,
        uint flags);

    public D2IShadowReferenceForm(bool nonActivating)
    {
        this.nonActivating = nonActivating;
    }

    protected override bool ShowWithoutActivation
    {
        get { return nonActivating; }
    }

    protected override CreateParams CreateParams
    {
        get
        {
            CreateParams parameters = base.CreateParams;
            if (nonActivating)
            {
                parameters.ExStyle |= WsExNoActivate;
            }
            return parameters;
        }
    }

    protected override void OnShown(EventArgs eventArgs)
    {
        base.OnShown(eventArgs);
        if (nonActivating)
        {
            SetWindowPos(
                Handle,
                HwndBottom,
                0,
                0,
                0,
                0,
                SwpNoSize | SwpNoMove | SwpNoActivate);
        }
    }
}
"@ -ReferencedAssemblies System.Windows.Forms

$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:ApprovedValue = 'D2I-SHADOW-APPROVED'
$script:Sequence = 0
$script:SaveRevision = 0
$script:CommandConsumed = $false
$script:ArmConsumed = $false
$script:Armed = $false
$script:InitialStateHash = $null

function Get-Sha256Text([string]$Text) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $script:Utf8NoBom.GetBytes($Text)
        $hash = $sha256.ComputeHash($bytes)
        return 'sha256:' + ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Write-AtomicJson([string]$Path, [object]$Value) {
    $temporary = "$Path.next"
    $json = $Value | ConvertTo-Json -Depth 8 -Compress
    [System.IO.File]::WriteAllText($temporary, $json, $script:Utf8NoBom)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

$form = [D2IShadowReferenceForm]::new($ReferenceMode -eq 'Instrumented')
$form.Text = $WindowTitle
$form.Size = [System.Drawing.Size]::new(680, 390)
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

$heading = [System.Windows.Forms.Label]::new()
$heading.Name = 'fixture-heading'
$heading.Text = 'D2I General Office Shadow Reference'
$heading.Location = [System.Drawing.Point]::new(24, 20)
$heading.Size = [System.Drawing.Size]::new(420, 24)
$form.Controls.Add($heading)

$nameInput = [System.Windows.Forms.TextBox]::new()
$nameInput.Name = 'employee-name-input'
$nameInput.AccessibleName = 'Employee name input'
$nameInput.Text = if ($Scenario -eq 'already_correct') { $script:ApprovedValue } else { 'INITIAL-VALUE' }
$nameInput.Location = [System.Drawing.Point]::new(24, 58)
$nameInput.Size = [System.Drawing.Size]::new(300, 24)
$form.Controls.Add($nameInput)

$applyButton = [System.Windows.Forms.Button]::new()
$applyButton.Name = 'apply-approved-button'
$applyButton.AccessibleName = 'Apply approved value'
$applyButton.Text = 'Apply approved value'
$applyButton.Location = [System.Drawing.Point]::new(340, 56)
$applyButton.Size = [System.Drawing.Size]::new(170, 30)
$form.Controls.Add($applyButton)

$saveButton = [System.Windows.Forms.Button]::new()
$saveButton.Name = 'save-button'
$saveButton.AccessibleName = 'Save record'
$saveButton.Text = 'Save record'
$saveButton.Location = [System.Drawing.Point]::new(24, 104)
$saveButton.Size = [System.Drawing.Size]::new(140, 30)
$form.Controls.Add($saveButton)

$clarifyButton = [System.Windows.Forms.Button]::new()
$clarifyButton.Name = 'clarify-button'
$clarifyButton.AccessibleName = 'Request clarification'
$clarifyButton.Text = 'Request clarification'
$clarifyButton.Location = [System.Drawing.Point]::new(180, 104)
$clarifyButton.Size = [System.Drawing.Size]::new(170, 30)
$form.Controls.Add($clarifyButton)

$escalateButton = [System.Windows.Forms.Button]::new()
$escalateButton.Name = 'escalate-button'
$escalateButton.AccessibleName = 'Escalate exception'
$escalateButton.Text = 'Escalate exception'
$escalateButton.Location = [System.Drawing.Point]::new(366, 104)
$escalateButton.Size = [System.Drawing.Size]::new(160, 30)
$form.Controls.Add($escalateButton)

$savedName = [System.Windows.Forms.TextBox]::new()
$savedName.Name = 'saved-name'
$savedName.AccessibleName = 'Saved value'
$savedName.Text = if ($Scenario -eq 'already_correct') { $script:ApprovedValue } else { 'INITIAL-VALUE' }
$savedName.ReadOnly = $true
$savedName.Location = [System.Drawing.Point]::new(24, 162)
$savedName.Size = [System.Drawing.Size]::new(300, 24)
$form.Controls.Add($savedName)

$revision = [System.Windows.Forms.TextBox]::new()
$revision.Name = 'save-revision'
$revision.AccessibleName = 'Save revision'
$revision.Text = '0'
$revision.ReadOnly = $true
$revision.Location = [System.Drawing.Point]::new(340, 162)
$revision.Size = [System.Drawing.Size]::new(90, 24)
$form.Controls.Add($revision)

$saveStatus = [System.Windows.Forms.TextBox]::new()
$saveStatus.Name = 'save-status'
$saveStatus.AccessibleName = 'Save status'
$saveStatus.Text = 'idle'
$saveStatus.ReadOnly = $true
$saveStatus.Location = [System.Drawing.Point]::new(446, 162)
$saveStatus.Size = [System.Drawing.Size]::new(170, 24)
$form.Controls.Add($saveStatus)

$finishButton = [System.Windows.Forms.Button]::new()
$finishButton.Name = 'finish-button'
$finishButton.AccessibleName = 'Finish reference step'
$finishButton.Text = 'Finish reference step'
$finishButton.Location = [System.Drawing.Point]::new(24, 220)
$finishButton.Size = [System.Drawing.Size]::new(190, 32)
$form.Controls.Add($finishButton)

$privacy = [System.Windows.Forms.Label]::new()
$privacy.Name = 'privacy-status'
$privacy.Text = 'App-local semantic events only'
$privacy.Location = [System.Drawing.Point]::new(24, 286)
$privacy.Size = [System.Drawing.Size]::new(420, 24)
$form.Controls.Add($privacy)

$referenceControls = @(
    $nameInput,
    $applyButton,
    $saveButton,
    $clarifyButton,
    $escalateButton,
    $finishButton
)
foreach ($control in $referenceControls) {
    $control.Enabled = $false
}

function Get-StateHash {
    $material = @(
        Get-Sha256Text $nameInput.Text
        Get-Sha256Text $savedName.Text
        $saveStatus.Text
        $revision.Text
    ) -join '|'
    return Get-Sha256Text $material
}

function Write-State {
    $state = [ordered]@{
        schema_version = 1
        ready = $true
        scenario_id = $Scenario
        recorder_mode = $ReferenceMode.ToLowerInvariant()
        input_sha256 = Get-Sha256Text $nameInput.Text
        saved_value_sha256 = Get-Sha256Text $savedName.Text
        save_status_id = $saveStatus.Text
        save_revision = $script:SaveRevision
        state_sha256 = Get-StateHash
        semantic_event_count = $script:Sequence
        completed = $saveStatus.Text -in @('saved', 'already-correct', 'clarification-requested', 'escalated', 'unsupported', 'human-error')
    }
    Write-AtomicJson $StatePath $state
}

function Write-SemanticEvent(
    [string]$OperationClass,
    [string]$DecisionClass,
    [string]$CapabilityClass,
    [string]$SemanticTarget,
    [string]$ResultClass,
    [string]$PreStateHash,
    [string]$PostStateHash
) {
    $script:Sequence += 1
    $event = [ordered]@{
        schema_version = 1
        sequence = $script:Sequence
        operation_class_id = $OperationClass
        decision_class_id = $DecisionClass
        capability_classification_id = if ($CapabilityClass) { $CapabilityClass } else { $null }
        semantic_target_id = if ($SemanticTarget) { $SemanticTarget } else { $null }
        approved_argument_artifact_sha256 = if ($CapabilityClass) { Get-Sha256Text $script:ApprovedValue } else { $null }
        pre_state_sha256 = $PreStateHash
        post_state_sha256 = $PostStateHash
        result_class_id = $ResultClass
        recorder_source_id = 'app-local-winforms-semantic-events-v1'
        raw_input_stored = $false
        raw_locator_stored = $false
        keylogging_used = $false
        mouse_hook_used = $false
        screenshot_used = $false
        clipboard_used = $false
        occurred_at_unix_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    }
    $line = ($event | ConvertTo-Json -Depth 6 -Compress) + [Environment]::NewLine
    [System.IO.File]::AppendAllText($EventPath, $line, $script:Utf8NoBom)
    Write-State
}

function Invoke-ReferenceOperation([string]$Operation) {
    $pre = Get-StateHash
    switch ($Operation) {
        'save' {
            $nameInput.Text = $script:ApprovedValue
            $savedName.Text = $nameInput.Text
            $script:SaveRevision += 1
            $revision.Text = $script:SaveRevision.ToString()
            $saveStatus.Text = 'saved'
            Write-SemanticEvent 'office.record.update' 'act' 'uia.set_value' 'employee_name_input' 'applied' $pre (Get-StateHash)
        }
        'already_correct' {
            $saveStatus.Text = 'already-correct'
            Write-SemanticEvent 'office.record.verify' 'no_action' '' '' 'already_satisfied' $pre (Get-StateHash)
        }
        'clarify' {
            $saveStatus.Text = 'clarification-requested'
            Write-SemanticEvent 'office.record.clarify' 'clarify' '' '' 'clarification_required' $pre (Get-StateHash)
        }
        'escalate' {
            $saveStatus.Text = 'escalated'
            Write-SemanticEvent 'office.record.escalate' 'escalate' '' '' 'escalated' $pre (Get-StateHash)
        }
        'human_error' {
            $nameInput.Text = 'REFERENCE-ERROR'
            $saveStatus.Text = 'human-error'
            Write-SemanticEvent 'office.record.update' 'act' 'uia.set_value' 'employee_name_input' 'rejected_by_verifier' $pre (Get-StateHash)
        }
        'unsupported' {
            $saveStatus.Text = 'unsupported'
            Write-SemanticEvent 'office.record.unsupported' 'refuse' '' '' 'unsupported' $pre (Get-StateHash)
        }
        default { throw "Unknown bounded reference operation: $Operation" }
    }
}

$applyButton.Add_Click({ $nameInput.Text = $script:ApprovedValue })
$saveButton.Add_Click({ Invoke-ReferenceOperation 'save' })
$clarifyButton.Add_Click({ Invoke-ReferenceOperation 'clarify' })
$escalateButton.Add_Click({ Invoke-ReferenceOperation 'escalate' })
$finishButton.Add_Click({
    if ($script:Sequence -eq 0) {
        if ($Scenario -eq 'already_correct') {
            Invoke-ReferenceOperation 'already_correct'
        }
        else {
            [System.Windows.Forms.MessageBox]::Show('Choose one reference action before finishing.', 'D2I Shadow') | Out-Null
            return
        }
    }
    $form.Close()
})

$commandTimer = [System.Windows.Forms.Timer]::new()
$commandTimer.Interval = 100
$commandTimer.Add_Tick({
    if (-not $script:ArmConsumed -and (Test-Path -LiteralPath $ArmPath -PathType Leaf)) {
        $arm = Get-Content -Raw -LiteralPath $ArmPath | ConvertFrom-Json
        $armFields = @($arm.PSObject.Properties.Name)
        if (
            $armFields.Count -ne 3 -or
            @($armFields | Where-Object { $_ -notin @('schema_version', 'operation', 'arm_token') }).Count -ne 0 -or
            $arm.schema_version -ne 1 -or
            $arm.operation -ne 'enable_reference_action' -or
            $arm.arm_token -cne $ArmToken
        ) {
            throw 'Reference action arm marker is malformed or does not match this session.'
        }
        $script:ArmConsumed = $true
        $script:Armed = $true
        foreach ($control in $referenceControls) {
            $control.Enabled = $true
        }
    }
    if (
        -not $script:Armed -or
        $ReferenceMode -ne 'Instrumented' -or
        $script:CommandConsumed -or
        -not (Test-Path -LiteralPath $CommandPath -PathType Leaf)
    ) {
        return
    }
    $command = Get-Content -Raw -LiteralPath $CommandPath | ConvertFrom-Json
    if ($command.schema_version -ne 1 -or $command.operation -notin @('save', 'already_correct', 'clarify', 'escalate', 'human_error', 'unsupported')) {
        throw 'Instrumented command is malformed or outside the bounded operation set.'
    }
    $script:CommandConsumed = $true
    Invoke-ReferenceOperation $command.operation
})

$form.Add_Shown({
    $form.Update()
    $script:InitialStateHash = Get-StateHash
    Write-State
    [System.IO.File]::WriteAllText($ReadyPath, (Get-Sha256Text $WindowTitle), $script:Utf8NoBom)
    $commandTimer.Start()
})

$form.Add_FormClosed({ $commandTimer.Stop() })
[System.Windows.Forms.Application]::Run($form)

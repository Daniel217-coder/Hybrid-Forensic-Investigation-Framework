rule CYBERSHADOW_DEMO_Onion
{
  meta:
    severity = "high"
    family = "ioc"
  strings:
    $onion = ".onion" nocase
  condition:
    $onion
}

rule CYBERSHADOW_DEMO_RuntimeExec
{
  meta:
    severity = "medium"
    family = "suspicious"
  strings:
    $re = "Runtime.getRuntime().exec" nocase
    $pb = "ProcessBuilder" nocase
  condition:
    any of them
}

rule CYBERSHADOW_DEMO_Insecure_HTTP
{
  meta:
    severity = "low"
    family = "network"
  strings:
    $h1 = "http://" nocase
  condition:
    $h1
}

rule CYBERSHADOW_DEMO_Sms_And_Internet
{
  meta:
    severity = "high"
    family = "combo"
  strings:
    $sms1 = "android.permission.READ_SMS" nocase
    $sms2 = "android.permission.RECEIVE_SMS" nocase
    $sms3 = "android.telephony.SmsManager" nocase
    $net1 = "android.permission.INTERNET" nocase
  condition:
    (any of ($sms*)) and $net1
}

rule CYBERSHADOW_DEMO_Accessibility_Abuse
{
  meta:
    severity = "high"
    family = "abuse"
  strings:
    $acc1 = "android.permission.BIND_ACCESSIBILITY_SERVICE" nocase
    $acc2 = "AccessibilityService" nocase
    $acc3 = "TYPE_WINDOW_CONTENT_CHANGED" nocase
  condition:
    2 of them
}

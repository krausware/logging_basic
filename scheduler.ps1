$eventaction = New-ScheduledTaskAction 
    -execute 'powershell.exe'
    -argument -file C:\backup_logs\Event_scraper.ps1
$eventtrigger = New-ScheduledTaskTrigger -Daily -at 8PM
$taskname = 'Scraping the logs boss'
$description = 'looking for common signs of system compromise'

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $eventaction `
    -Trigger $eventrigger `
    -Description $description
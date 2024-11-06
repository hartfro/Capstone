#include "headers.h"

// The task will run every day at 12:00 PM

void CreateScheduledTaskWithCurrentPath() {
    WCHAR path[MAX_PATH];
    WCHAR command[1024];

    // Get the current executable's path
    if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
        //printf("Failed to get executable path. Error: %ld\n", GetLastError());
        return;
    }

    // Prepare the schtasks command
    // /SC DAILY schedules the task to run daily
    // /ST "12:00" sets the task to run at 12:00 PM
    // /RL HIGHEST ensures the task runs with the highest privileges
    // /F forces the creation of the task if one with the same name exists
    swprintf(command, 1024,
        L"schtasks /create /tn \"RunMyProgramAtStartup\" /tr \"%s\" /sc daily /st 23:32 /rl highest /f /ru \"SYSTEM\"", path);

    // Run the schtasks command
    _wsystem(command);

    //wprintfL"Task created to run daily at 12:00 PM: %s\n", path);

}
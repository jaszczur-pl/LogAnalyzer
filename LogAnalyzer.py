#!/usr/bin/env python3
import win32evtlog
import csv
import xlsxwriter

csv_file_path = "C:\\Users\\Maciek\\Desktop\\security_report.csv"
excel_file_path = "C:\\Users\\Maciek\\Desktop\\security_report.xlsx"
workstation = "localhost"
logtype = "Security"
hand = win32evtlog.OpenEventLog(workstation, logtype)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)

event_dictionary = {4624: "Account was successfully logged on",
                    4634: "Account was logged off",
                    4625: "Account failed to log on",
                    4608: "Windows is starting up",
                    4720: "New account was created: ",
                    4725: "Account was disabled: ",
                    4726: "Account was deleted: ",
                    4722: "Account was enabled: ",
                    4740: "Account was locked out: ",
                    4767: "Account was unlocked: "}


def write_to_excel(matrix):
    workbook = xlsxwriter.Workbook(excel_file_path)
    worksheet = workbook.add_worksheet("report")
    row = 1
    col = 0
    worksheet.write_row('A1', ('timestamp', 'event ID', 'message', 'user', 'source', 'computer'))
    for time, event_ID, message, user, source, computer in (matrix):
        worksheet.write(row, col, time)
        worksheet.write(row, col + 1, event_ID)
        worksheet.write(row, col + 2, message)
        worksheet.write(row, col + 3, user)
        worksheet.write(row, col + 4, source)
        worksheet.write(row, col + 5, computer)
        row +=1
    workbook.close()


def write_to_csv(matrix):
    with open(csv_file_path,mode='w') as csv_file:
        csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerows(matrix)
        csv_file.close()


def read_events():
    matrix = []
    event_no = 0
    while 1:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                if event.EventID in event_dictionary:
                    data = event.StringInserts
                    computer = event.ComputerName
                    message = event_dictionary.get(event.EventID)
                    event_time = str(event.TimeGenerated)

                    if event.EventID == 4624 or event.EventID == 4625:
                        user = data[5]
                    elif event.EventID == 4634:
                        user = data[1]
                    elif event.EventID == 4608:
                        user = "N/A"
                    elif event.EventID == 4720 or event.EventID == 4725 or event.EventID == 4726 \
                            or event.EventID == 4722 or event.EventID == 4740 or event.EventID == 4767:
                        user = data[4]
                        account_name = data[0]
                        message += account_name

                    single_row = [event_time, event.EventID, message, user, 'Windows Security Event Log', computer]
                    matrix.append(single_row)
                event_no += 1
                if event_no >= total:
                    print ("Logon/logoff data gathered from Windows Security event log.")
                    win32evtlog.CloseEventLog(hand)
                    print("number of processed records: " + str(event_no))
                    return matrix


if __name__ == '__main__':
    matrix = read_events()
    write_to_csv(matrix)
    write_to_excel(matrix)

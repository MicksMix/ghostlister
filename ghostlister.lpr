program ghostlister;

//
// author: Mick Grove
// date: Feb 23, 2011
//
{$mode delphi}{$H+}

//{$IFDEF WINDOWS}{$R ghostlister.rc}{$ENDIF}

uses
  Windows,
  SysUtils,
  uPsAPI;

type
  EGetoptException = class(Exception)
  private
    FOptind:   integer;
    FParamStr: string;
    FOffendingOption: string;
  public
    property OffendingOption: string read FOffendingOption write FOffendingOption;
    property Optind: integer read FOptind write FOptind;
    property ParamStr: string read FParamStr write FParamStr;
  end;

type
  EListOfStringError = class(Exception);

type
  //this type is to avoid use of TStringList, which brings the 'Classes' unit along with it
  TListOfString = class(TObject)
  private
    FLstItems: array of string;
    function GetCount: integer; inline;
    function GetItem(index: integer): string;
    procedure SetItem(index: integer; const val: string);
  public
    function Add(const item: string): integer; inline;
    procedure Clear;
    procedure Delete(Index: integer);
    function IndexOf(s: string): integer;
    property Count: integer read GetCount;
    property Items[index: integer]: string read GetItem write SetItem; default;
  end;


  function GetModuleBaseName(hProcess: THandle; module: HInst;
    BaseName: PChar; size: integer): integer;
  stdcall; external 'psapi.dll' Name 'GetModuleBaseNameA';


const
  SE_DEBUG_NAME = 'SeDebugPrivilege';
  SZ_IMAGE_NAME = 128;
  MIN_PID = $0;
  MAX_PID = $4E1C; //19996
  PID_INC = $4;

var
  slBruteForceProcs, slBruteForceProcInfo, slStandardProcs : TListOfString;

  ///
  ///
  ///

  procedure QuickSort(var Strings: TListOfString; Start, Stop: integer);
  var
    Left :  integer;
    Right : integer;
    Mid :   integer;
    Pivot : string;
    Temp :  string;
  begin
    Left  := Start;
    Right := Stop;
    Mid   := (Start + Stop) div 2;

    Pivot := Strings[mid];
    repeat
      while Strings[Left] < Pivot do
        Inc(Left);
      while Pivot < Strings[Right] do
        Dec(Right);
      if Left <= Right then
      begin
        Temp := Strings[Left];
        Strings[Left] := Strings[Right]; // Swaps the two Strings
        Strings[Right] := Temp;
        Inc(Left);
        Dec(Right);
      end;
    until Left > Right;

    if Start < Right then
      QuickSort(Strings, Start, Right); // Uses
    if Left < Stop then
      QuickSort(Strings, Left, Stop);     // Recursion
  end;

  function TListOfString.Add(const item: string): integer;
  begin
    SetLength(FLstItems, Count + 1);
    FLstItems[Count - 1] := item;
    Result := Count - 1;
  end;

  procedure TListOfString.Clear;
  begin
    SetLength(FLstItems, 0);
  end;

  procedure TListOfString.Delete(Index: integer);
  begin
    if (Index < 0) or (Index >= Count) then
    begin
      raise EListOfStringError.Create('List index out of bounds');
    end;

    if Index < Count - 1 then
    begin
      FLstItems[Index] := '';             // release the memory
      move(FLstItems[Index + 1], FLstItems[Index], SizeOf(FLstItems[0]) *
        (Count - Index - 1));
      PPointer(@FLstItems[Count - 1])^ := nil;
    end;

    SetLength(FLstItems, Count - 1);
  end;

  function TListOfString.GetCount: integer;
  begin
    Result := Length(FLstItems);
  end;

  function TListOfString.GetItem(index: integer): string;
  begin
    Result := FLstItems[index];
  end;

  function TListOfString.IndexOf(s: string): integer;
  var
    idx : integer;
  begin
    Result := -1;                         //default
    for idx := 0 to Count - 1 do
    begin
      if FLstItems[idx] = s then
      begin
        Result := idx;
        break;
      end;
    end;
  end;

  procedure TListOfString.SetItem(index: integer; const val: string);
  begin
    FLstItems[index] := val;
  end;

  function SetPrivilege(hToken: THandle; priv: string; enablePriv: boolean): boolean;
  var
    //hToken            : THandle;
    TpNew, TpOld, TpDummy : TTokenPrivileges;
    lpLuid : TLargeInteger;
    dwReturnLength : DWORD;
  begin

    //if disable all privileges = FALSE
    if LookupPrivilegeValue(nil, PChar(priv), lpLuid) then
    begin
      TpNew.PrivilegeCount := 1;
      TpNew.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
      TpNew.Privileges[0].Luid := lpLuid;
      Result := AdjustTokenPrivileges(hToken,                           //handle
        False,                             // DisableAllPrivileges
        TpNew,                             //newstate
        sizeof(TpNew),                     // buffer length
        TpDummy,//nil,                               //previous state
        dwReturnLength);                  //return length

      if GetLastError <> ERROR_SUCCESS then
      begin
        Result := False;
        Exit;
      end;
    end
    else
    begin
      Result := False;
      Exit;
    end;

    if enablePriv then
    begin
      TpOld.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    end
    else
    begin
      TpOld.Privileges[0].Attributes := 0;
    end;

    TpOld.PrivilegeCount     := 1;
    TpOld.Privileges[0].Luid := lpLuid;

    Result := AdjustTokenPrivileges(hToken,                             //handle
      False,                              // DisableAllPrivileges
      TpOld,                              //newstate
      sizeof(TpOld),                      // buffer length
      TpDummy,//nil,                                //previous state
      dwReturnLength);
    //dwReturnLength);                  //return length

    if GetLastError <> ERROR_SUCCESS then
    begin
      Result := False;
      Exit;
    end
    else
    begin
      Result := True;
    end;
    //CloseHandle(hToken);

  end;

  procedure PIDBruteForce();
  var
    pid, nProc, retSize : DWORD;
    procHandle, tokHandle : THandle;
    bIsValid : boolean;
    buffer :   array[0..MAX_PATH - 1] of char;
  begin

    bIsValid := OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES or
      TOKEN_QUERY, False, tokHandle);

    if not bIsValid then
    begin
      if GetLastError() = ERROR_NO_TOKEN then
      begin
        bIsValid := ImpersonateSelf(SecurityImpersonation);

        if not bIsValid then
        begin
          WriteLn('*** error: ImpersonateSelf failed');
          Exit;
        end;

        bIsValid := OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES or
          TOKEN_QUERY, False, tokHandle);

        if not bIsValid then
        begin
          WriteLn('*** error: OpenThreadToken failed');
          Exit;
        end;
      end
      else
      begin
        WriteLn('*** error: OpenThreadToken failed');
        Exit;
      end;
    end;

    bIsValid := SetPrivilege(tokHandle, SE_DEBUG_NAME, True);
    try
      if not bIsValid then
      begin
        WriteLn('*** error: SetPrivilege failed');
        //CloseHandle(tokHandle);
        Exit;
      end;

      pid   := MIN_PID;
      nProc := 0;
      while pid < MAX_PID do
      begin
        FillChar(Buffer, SizeOf(Buffer), 0); //clear buffer

        procHandle := OpenProcess(PROCESS_ALL_ACCESS, True, pid);

        if procHandle <> 0 then
        begin
          retSize := GetModuleBaseName(procHandle, 0, buffer, SZ_IMAGE_NAME);
          if retSize > 0 then
          begin
            //WriteLn(Format('pid [%04d] = %s', [pid, buffer]));
            slBruteForceProcInfo.Add(Format('pid [%04d] = %s', [pid, buffer]));
            slBruteForceProcs.Add(IntToStr(pid));
            Inc(nProc);
          end;
          CloseHandle(procHandle);
        end;

        pid := pid + PID_INC;
      end;

      //WriteLn(Format(#13#10 + 'Number of Processes = %d', [nProc]));
    finally
      CloseHandle(tokHandle);
    end;

  end;

  procedure SnapshotList();
  var
    SnapshotHandle : THandle;
    procEntry : PROCESSENTRY32;
    bIsValid :  boolean;
    nProc :     DWORD;
    iPos :      integer;
    sFilename : string;
  begin

    SnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if SnapshotHandle = INVALID_HANDLE_VALUE then
    begin
      WriteLn('*** error: CreateToolhelp32Snapshot failed');
      Exit;
    end;

    nProc := 0;
    try
      procEntry.dwSize := SizeOf(PROCESSENTRY32);
      bIsValid := Process32First(SnapshotHandle, procEntry);
      while bIsValid do
      begin
        if (procEntry.th32ProcessID = $0) or (procEntry.th32ProcessID = $4) then
        begin
          bIsValid := Process32Next(SnapshotHandle, procEntry);
          continue;
        end;

        iPos := slBruteForceProcs.IndexOf(IntToStr(procEntry.th32ProcessID));
        if iPos < 0 then //pid is not found in brute force list....very odd
        begin
          sFilename := UpperCase(Format('%s', [procEntry.szExeFile]));
          if sFilename <> 'AUDIODG.EXE' then
          begin
            slStandardProcs.Add(Format(#9'*** SUSPICIOUS pid [%04d] = %s',
              [procEntry.th32ProcessID, procEntry.szExeFile]));
            ;
            //Writeln(Format(#9'*** SUSPICIOUS pid [%04d] = %s',
            //  [procEntry.th32ProcessID, procEntry.szExeFile]));
          end
          else
          begin
            //we ignore this process --- its special
            //lets add it to the native list
            slBruteForceProcInfo.Add(Format('pid [%04d] = %s',
              [procEntry.th32ProcessID, procEntry.szExeFile]));
            //slBruteForceProcs.Add(IntToStr(procEntry.th32ProcessID));
          end;
          //slHiddenProcs.Delete
        end
        else
        begin
          slBruteForceProcs.Delete(iPos);
        end;

        slStandardProcs.Add(Format('pid [%04d] = %s',
          [procEntry.th32ProcessID, procEntry.szExeFile]));
        ;
        //Writeln(Format('pid [%04d] = %s', [procEntry.th32ProcessID,
        //  procEntry.szExeFile]));

        Inc(nProc);
        bIsValid := Process32Next(SnapshotHandle, procEntry);
      end;
    finally
      CloseHandle(SnapshotHandle);
    end;
    //WriteLn(Format(#13#10 + 'Standard Process Query count = %d', [nProc]));


    //  if not bIsValid then
    //  begin
    //    WriteLn('*** error: Process32First failed');
    //    CloseHandle(snapshotHandle);
    //    Exit;
    //  end;

  end;

  procedure ListThreadsByPID(pid: DWORD);
  var
    SnapshotHandle : THandle;
    threadEntry : THREADENTRY32;
    bIsValid : boolean;
    tid :      DWORD;
  begin

    SnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if SnapshotHandle = INVALID_HANDLE_VALUE then
    begin
      WriteLn('*** error: CreateToolhelp32Snapshot failed');
      Exit;
    end;

    threadEntry.dwSize := SizeOf(THREADENTRY32);
    bIsValid := Thread32First(SnapshotHandle, threadEntry);
    try
      if not bIsValid then
      begin
        WriteLn('*** error: Thread32First failed');
        Exit;
      end;

      while bIsValid do
      begin
        if threadEntry.th32OwnerProcessID = pid then
        begin
          tid := threadEntry.th32ThreadID;
          Writeln(Format('Tid = 0x%08X, %u', [tid, tid]));
        end;
        bIsValid := Thread32Next(SnapshotHandle, threadEntry);
      end;
    finally
      CloseHandle(SnapshotHandle);
    end;

  end;

var
  idx : integer;
begin
  try
    slBruteForceProcInfo := TListOfString.Create;
    slBruteForceProcs    := TListOfString.Create;
    slStandardProcs      := TListOfString.Create;
    try

      PIDBruteForce();
      SnapshotList();
      QuickSort(slStandardProcs, 0, slStandardProcs.Count - 1);
      for idx := 0 to slStandardProcs.Count - 1 do
      begin
        WriteLn(slStandardProcs[idx]);
      end;
      WriteLn(Format(#13#10 + 'Standard report of number of processes = %d',
        [slStandardProcs.Count]));
      WriteLn('++++++++++++++++++++++++++++++++++++++++++++' + #13#10);
      //PIDBruteForce();

      QuickSort(slBruteForceProcInfo, 0, slBruteForceProcInfo.Count - 1);
      for idx := 0 to slBruteForceProcInfo.Count - 1 do
      begin
        WriteLn(slBruteForceProcInfo[idx]);
      end;
      WriteLn(Format(#13#10 + 'Real Number of Processes = %d',
        [slBruteForceProcInfo.Count]));
      WriteLn('++++++++++++++++++++++++++++++++++++++++++++' + #13#10);

      WriteLn('Hidden PIDs found: ' + IntToStr(slBruteForceProcs.Count));
      for idx := 0 to slBRuteForceProcs.Count - 1 do
      begin
        WriteLn('Thread info for PID [' + slBRuteForceProcs[idx] + ']:');
        WriteLn('===========' + #13#10);
        ListThreadsByPID(StrToInt(slBRuteForceProcs[idx]));
      end;

    finally
      FreeAndNil(slStandardProcs);
      FreeAndNil(slBruteForceProcInfo);
      FreeAndNil(slBruteForceProcs);
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.


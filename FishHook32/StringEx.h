char* stristr(const char *pcString1, const char *pcString2)
{
 char *pCompareStart = (char *)pcString1;
 char *pCursor_S1, *pCursor_S2;
 char cSrc, cDst;
 
 // If there is a null source string - this is a "no match"
 
 if (!pcString1)
  return NULL;
  
 // Null length string 2 - this is a "no match"
 if (!*pcString2)
  return NULL;
  
 // Search from every start pos in the source string
 while (*pCompareStart)
 {
  pCursor_S1 = pCompareStart;
  pCursor_S2 = (char *)pcString2;
  
  // Scan both string
  
  while (*pCursor_S1 && *pCursor_S2)
  {
   cSrc = *pCursor_S1;
   cDst = *pCursor_S2;
   
   // Correct case
   
   if ((cSrc >= 'A') && (cSrc <= 'Z'))
    cSrc -= ('A' - 'a');
    
   if ((cDst >= 'A') && (cDst <= 'Z'))
    cDst -= ('A' - 'a');
    
   if (cSrc != cDst)
    break;
    
   pCursor_S1++;
   pCursor_S2++;
  }
  
  // If string 2 is exhausted - there is a match
  
  if (!*pCursor_S2)
   return(pCompareStart);
   
  // Offset source and continue
  pCompareStart++;
 }
 
 return NULL;
}
<?php // encrypters-decrypters.php

   // Implementation of simple substitution using ROT13, 
   // $encrypt decides whether the input is being encrypted
   // or decrypted.
   function simpleSub($input, $encrypt){
      $output = "";
      $delta = $encrypt ? 13 : -13;

      for ($i = 0; $i < strlen($input); $i++){
         $upperCase = false;
         $lowerCase = false;
         $value = ord($input[$i]);

         if ($value >= ord("A") && $value <= ord("Z")) $upperCase = TRUE;
         else if ($value >= ord("a") && $value <= ord("z")) $lowerCase = TRUE;
         
         // Substract/Add 26 in case the value goes outside the bounds of the
         // alphabet, resetting the rotation.
         if ($value+$delta > ord("z") || 
            ($upperCase && $value+$delta > ord("Z"))){

            $value = $value + $delta - 26; 

         }
         else if ($value+$delta < ord("a") && $lowerCase || 
                  $upperCase && $value+$delta < ord("A")){

            $value = $value + $delta + 26;

         }
         else if ($upperCase || $lowerCase){
            $value += $delta;
         }

         $output .= chr($value);
      }

      return $output;
   }
   
   
   function transpose($plaintext, $tmpKey)
{
	// Remove all non-letters and capitalize the letters.
	$plaintext = strtoupper(preg_replace('/[^a-zA-Z ]/', '', $plaintext));
    $tmpKey = strtoupper(preg_replace('/[^a-zA-Z]/', '', $tmpKey));
    $keySet = array("A"=>FALSE,"B"=>FALSE,"C"=>FALSE,
                    "D"=>FALSE,"E"=>FALSE,"F"=>FALSE,
                    "G"=>FALSE,"H"=>FALSE,"I"=>FALSE,
                    "J"=>FALSE,"K"=>FALSE,"L"=>FALSE,
                    "M"=>FALSE,"N"=>FALSE,"O"=>FALSE,
                    "P"=>FALSE,"Q"=>FALSE,"R"=>FALSE,
                    "S"=>FALSE,"T"=>FALSE,"U"=>FALSE,
                    "V"=>FALSE,"W"=>FALSE,"X"=>FALSE,
                    "Y"=>FALSE,"Z"=>FALSE);
    $key = "";

    // Loop through the keySet "used" characters to create a
    // Key without repetitions.
	for ($i = 0; $i < strlen($tmpKey); $i++){
        if ($keySet[$tmpKey[$i]] == FALSE){
            $key .= $tmpKey[$i];
            $keySet[$tmpKey[$i]] = TRUE;
        }
    }

	$keylen = strlen($key);

	while(strlen($plaintext) % $keylen != 0)
	{
		$plaintext .= " "; // pad with Q's if the length of the input cannot be divided with keylen evenly
	}
	$columnlen = strlen($plaintext) / strlen($key);


	$alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	$ciphertext = "";
	$cipher1 = "";
	$a = 0;
		
	for($i = 0; $i < $keylen; $i++)
	{
		while($a < 26)
		{
			$letterPos = strpos($key, $alphabet[$a]);
			$a++;
			if($letterPos !== FALSE)
			{
				break;
			}
		}
		for($c = 0; $c < $columnlen; $c++)
		{
			$cipher1 .= $plaintext[$keylen * $c + $letterPos];
		}
	}
	// Transpose again.
	$a = 0;
	for($i = 0; $i < $keylen; $i++)
	{
		while($a < 26)
		{
			$letterPos = strpos($key, $alphabet[$a]);
			$a++;
			if($letterPos !== FALSE)
			{
				break;
			}
		}
		for($c = 0; $c < $columnlen; $c++)
		{
			$ciphertext .= $cipher1[$keylen * $c + $letterPos];
		}
	}

	return $ciphertext;
}

function detranspose($ciphertext, $tmpKey)
{
	// Remove all non-letters and capitalize the letters.
	$ciphertext = strtoupper(preg_replace('/[^a-zA-Z ]/', '', $ciphertext));
	$tmpKey = strtoupper(preg_replace('/[^a-zA-Z]/', '', $tmpKey));
    $keySet = array("A"=>FALSE,"B"=>FALSE,"C"=>FALSE,
                    "D"=>FALSE,"E"=>FALSE,"F"=>FALSE,
                    "G"=>FALSE,"H"=>FALSE,"I"=>FALSE,
                    "J"=>FALSE,"K"=>FALSE,"L"=>FALSE,
                    "M"=>FALSE,"N"=>FALSE,"O"=>FALSE,
                    "P"=>FALSE,"Q"=>FALSE,"R"=>FALSE,
                    "S"=>FALSE,"T"=>FALSE,"U"=>FALSE,
                    "V"=>FALSE,"W"=>FALSE,"X"=>FALSE,
                    "Y"=>FALSE,"Z"=>FALSE);
    $key = "";

    // Loop through the keySet "used" characters to create a
    // Key without repetitions.
    for ($i = 0; $i < strlen($tmpKey); $i++){
        if ($keySet[$tmpKey[$i]] == FALSE){
            $key .= $tmpKey[$i];
            $keySet[$tmpKey[$i]] = TRUE;
        }
    }

	$keylen = strlen($key);

	if(strlen($ciphertext) % $keylen != 0)// If the key provided doesn't divide the cipher text correctly
	{// This means that the key cannot decipher the ciphertext.
		echo "Your key doesn't work for the cipher text...";
		return;
	}
	$columnlen = strlen($ciphertext) / strlen($key);


	$alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	$plaintext = "";
	$plain1 = "";
	
	// Individual columns from the cipher text.
	$columns = array($keylen);

	for($i = 0; $i < $keylen; $i++)
	{
		$columns[$i] = substr($ciphertext, $columnlen * $i, $columnlen);
	}
	// Rearranged will hold the proper order of the columns before decrypting.
	$rearranged = array();
	$c = 0;
	$a = 0;
	while($c < $keylen)// We will only loop through the cipher based on key lenght
	{
		$letterPos = strpos($key, $alphabet[$a]);// Position of a letter in the key.
		$a++;// Keep moving through the alphabet.
		if($letterPos !== FALSE)// We rearrange the columns based on the key
		{// If the current letter pointed in the alphabet is in the key, there should be a letter position.
			$rearranged[$letterPos] = $columns[$c];
			$c++; // Only move the loop when a column is successfully put in the right spot.
		}
	}
	for($l = 0; $l < $columnlen; $l++)
	{
		for($c = 0; $c < $keylen; $c++)// Cycle through the columns
		{	//Get the $cth letter from the current column and add it to the plaintext.
			$plain1 .= $rearranged[$c][$l];
		}
	}

	// Transpose one more timeu
	unset($columns);
	$columns = array();

	for($i = 0; $i < $keylen; $i++)
	{
		$columns[$i] = substr($plain1, $columnlen * $i, $columnlen);
	}
	// Rearranged will hold the proper order of the columns before decrypting.
	$rearranged = array($keylen);
	$c = 0;
	$a = 0;
	while($c < $keylen)// We will only loop through the cipher based on key lenght
	{
		$letterPos = strpos($key, $alphabet[$a]);// Position of a letter in the key.
		$a++;// Keep moving through the alphabet.
		if($letterPos !== FALSE)// We rearrange the columns based on the key
		{// If the current letter pointed in the alphabet is in the key, there should be a letter position.
			$rearranged[$letterPos] = $columns[$c];
			$c++; // Only move the loop when a column is successfully put in the right spot.
		}
	}
	for($l = 0; $l < $columnlen; $l++)
	{
		for($c = 0; $c < $keylen; $c++)// Cycle through the columns
		{	//Get the $cth letter from the current column and add it to the plaintext.
			$plaintext .= $rearranged[$c][$l];
		}
	}

	return $plaintext;
}
   
   
   // RC4 Cipher, encrypts and decrypts as long as the same key is provided for both.
	function rivest($text, $key, $encrypt)
	{
		$s = array(256); // Array for bits [0, 255]
		// Initialize the 256 Bits of S
		for($i = 0; $i < 256; $i++)
		{
			$s[$i] = $i;
		}

		$keylen = strlen($key);
		$textlen = strlen($text);
		$k = array(256); // Array to contain the repeated key.
		// Initialize $k with the key, repeating until full.
		for($i = 0; $i < 256; $i++)
		{
			$k[$i] = ord($key[$i % $keylen]); // Cycle through the key, storing each byte into $k
		}

		// This is the Key Scheduling Algorithm (KSA)
		$j = 0;
		for($i = 0; $i < 256; $i++)
		{
			$j = ($j + $s[$i] + $k[$i]) % 256;
			swap($s[$i], $s[$j]);
			//$temp = $s[$i];
			//$s[$i] = $s[$j];
			//$s[$j] = $temp;
			//See swap below.
		}
			
		$j = 0; // Set j back to 0 for the Pseudo Random Generation Algorithm
		$keystream = array($textlen);
		for($i = 0; $i < 256; $i++) // This loop discards the first 256 bytes generated.
		{			// but it is usually safer to discard as many bytes as possible
			// as long as the decryption does the same, which in this case, it does.
			// The discarding prevents attacks from related characters. The ciphertext also seem
			// to have cycled completely, avoiding character retentions.
			$j = $j + $s[$i] % 256;
			swap($s[$i], $s[$j]);
		}
		$j = 0;
		for($i = 0; $i < $textlen; $i++)
		{
			$j = $j + $s[$i] % 256;
			swap($s[$i], $s[$j]);
			$t = ($s[$i] + $s[$j]) % 256;
			$keystream[$i] = $s[$t];// We store the the generated byte into the keystream.
		}

		$ciphered = "";
		if($encrypt != 1)
		{// decryption
			$textArray = array();
			$t = 0;	
			for($i = 0; $i < strlen($text); $i+=3)
			{
				$char = substr($text, $i, 3);
				$textArray[$t] = intval($char);
				$t++;
			}
			for($i = 0; $i < $textlen/3; $i++)
			{
				$ciphered .= chr($keystream[$i] ^ $textArray[$i]);
			}
		}
		else// encryption here
		{
			for($i = 0; $i < $textlen; $i++)
			{
				$ciphered .= str_pad($keystream[$i] ^ ord($text[$i]), 3, "0", STR_PAD_LEFT);// pads with 0's
													// space for visual	
			}
		}
		return $ciphered;

	}
   

   // Swaps two items passed by reference, using a temporary variable.
   function swap(&$x, &$y)
   {
       $temp = $x;
       $x = $y;
       $y = $temp;
   }
   
   // DES
   function des($plaintext, $key)
   {// key has to be 64 bits or 8 bytes
       
       $kbyte = substr($key, 0, 8);
       $kblock = bytesbits($kbyte); //store
       
       //$test = array(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,
       //	31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64);
       //	You can use this test to see if the permutation is actually applied correctly, simply change kblock
       //	in the forloop below to test.
       
       // The Key Scheduling starts here
       // ****************************************************************************
       // Permutation for the 64-bit key block before the shiftings.
       $pc1 = array(57, 49, 41, 33, 25, 17, 9,
           1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4);
       $pkey = array(56);
       
       // PC1 Permutation for the key using the pc1 table above.
       for($i = 0; $i < 56; $i++)
       {
           $pkey[$i] = $kblock[$pc1[$i]-1];
       }
       /*
        for($i = 0; $i < 56; $i++)
        {
        echo $pkey[$i]. "<br>"; // Print test for the permutation.
        }*/
       
       $subkeys = array(16); //There will be 16 subkeys, initializing here.
       
       // Shiftings to produce 16 keys that will be permutated again using PC2.
       // The permutation above will be split in half and shifted separately
       // each half is 28-bits, will be stored in leftsub and rightsub temporarily
       // Each level of shifting varies according to the following table.
       $shifts = array(1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1);
       
       $leftsub = array(28); // to hold 28 bits of the left side of the subkey
       $rightsub = array(28);
       
       $leftrightsub = array_chunk($pkey, 28, false); // Chunks/splits the subkeys into two 32 bits.
       // Assign the two halves into left and right accrodingly.
       $leftsub = $leftrightsub[0];
       $rightsub = $leftrightsub[1];
       
       //print_r($leftsub); test print, work fine!
       
       // Do the shifts and concatenate left and right to their corresponding subkeys index.
       
       for($i = 0; $i < 16; $i++) // for the 16 subkeys
       {
           // left side
           for($s = 0; $s < $shifts[$i]; $s++)// Shift amount based on the table above.
           {
               $topbit = $leftsub[0]; // save the msb before shifting.
               for($j = 1; $j < 28; $j++)
               {
                   $leftsub[$j-1] = $leftsub[$j]; // shift one at a time. I know this feels so slow.
               }
               $leftsub[27] = $topbit; // put the top bit into the lsb spot
           }
           
           // right side
           for($s = 0; $s < $shifts[$i]; $s++)// Shift amount based on the table above.
           {
               $topbit = $rightsub[0]; // save the msb before shifting.
               for($j = 1; $j < 28; $j++)
               {
                   $rightsub[$j-1] = $rightsub[$j]; // shift one at a time. I know this feels so slow.
               }
               $rightsub[27] = $topbit; // put the top bit into the lsb spot
           }
           // merge the two sides and store in subkeys.
           $subkeys[$i] = array_merge($leftsub, $rightsub);
       }
       //print_r($subkeys[15]); //tested the result for one of the shifts, look alright
       // The first and last subkey turned out to be the same permutation. interesting...
       
       // Now we need to permute each subkey again, using the following table.
       // Interestingly enough, this permutation further reduces the subkey lenghts
       // from 56-bits to 48-bits, which will match the reduction in the input text later on
       $pc2 = array(14, 17, 11, 24, 1, 5,
           3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8,
           16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32);
       // Similar to the PC1 permutation.
       // PC2 Permutation for the subkeys using the pc2 table above.
       $finalsk = array(16);
       for($s = 0; $s < 16; $s++)// For each subkey, we permute.
       {
           $tempkey = array(48);
           for($i = 0; $i < 48; $i++)
           {
               $tempkey[$i] = $subkeys[$s][$pc2[$i]-1];
           }
           $finalsk[$s] = $tempkey;
       }
       //print_r($finalsk[0]); // I walked through this, the permutation works! Whew.
       // finalsk now holds the keys to be used in the cipher, that took soo much work for key scheduling lol.
       // ****************************************************************************
       // Key Scheduling ends here!
       
       // Now that we have the subkeys ready! We start chunking the input into 64-bit blocks and do 16 rounds of permutations and so forth.
       // Each round will use the corresponding key that was generated earlier. Each 64-bit block will undergo the same process
       // repeating until all the bytes in the text is converted to cipher text. Maybe I should padd the plain text with some A's or something
       // to ensure that the blocks are always 64-bits because I am not sure if the logic stays in tact with size other than 64. Same with the
       // key...
       
       // Initial Permutation of the 64-bit block from the plain text.
       $ip = array(58, 50, 42, 34, 26, 18, 10, 2,
           60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6,
           64, 56, 48, 40, 32, 24, 16, 8,
           57, 49, 41, 33, 25, 17, 9, 1,
           59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5,
           63, 55, 47, 39, 31, 23, 15, 7);
       
       
       $ptlen = strlen($plaintext);
       $numblocks = ceil($ptlen / 8); // There are this many blocks in the plaintext.
       
       $ciphertext = "";
       for($m = 0; $m < $numblocks; $m++) // Run as much as the number of blocks.
       {
           
           $pbytes = substr($plaintext, ($m * 8), 8); // Get 8 bytes from the plain text.
           //echo "<br> $pbytes <br>";
           $pblock = bytesbits($pbytes);
           //print_r($pblock);
           $ptext = array(64);// Stores the 64-bits of this block from the plain text.
           
           // Permute the block based on the initial permutation table above.
           for($i = 0; $i < 64; $i++)
           {
               $ptext[$i] = $pblock[$ip[$i]-1];
           }
           // $ptext now holds a bit format of an 8-byte(64-bits) of the plaintext and is permuted using the IP table above.
           $leftpt = array(32);
           $rightpt = array(32);
           $leftrightpt = array_chunk($ptext, 32, false);
           
           $leftpt = $leftrightpt[0];
           $rightpt = $leftrightpt[1];
           
           //print_r($leftpt);
           
           // 16 rounds for the block using the 16 subkeys generated earlier.
           
           for($i = 0; $i < 16 ; $i++) // 16 rounds
           {
               $lefttemp = $rightpt;
               $erxorkres = erxork($rightpt, $finalsk[$i]);
               $rightside = shrink($erxorkres);
               $righttemp = array(32);
               for($j = 0; $j < 32; $j++) // Left Xor (Expanded Right Xor Key) side for the Right
               {
                   $righttemp[$j] = $leftpt[$j] ^ $rightside[$j];
               }
               $leftpt = $lefttemp;
               $rightpt = $righttemp;
           }
           // Then at the last step, we swap Left and Right, merge, then permute them one last time using IP table.
           $result = array_merge($rightpt, $leftpt);
           
           $ip = array(40, 8, 48, 16, 56, 24, 64, 32,
               39, 7, 47, 15, 55, 23, 63, 31,
               38, 6, 46, 14, 54, 22, 62, 30,
               37, 5, 45, 13, 53, 21, 61, 29,
               36, 4, 44, 12, 52, 20, 60, 28,
               35, 3, 43, 11, 51, 19, 59, 27,
               34, 2, 42, 10, 50, 18, 58, 26,
               33, 1, 41, 9, 49, 17, 57, 25);
           $presult = array(64);
           for($i = 0; $i < 64; $i++)
           {
               $presult[$i] = $result[$ip[$i]-1];
           }
           //print_r($presult);
           // Now we can chunk the presult into 4 bits to save in the cipher text as a character each.
           $splitresult = array_chunk($presult, 4, false); // There are 16 4-bit groups in a 64-bit sequence.
           echo "<br>";
           //print_r($splitresult);
           
           for($i = 0; $i < 16; $i++)
           {
               $character = "";
               // Consolidate the separate bits into a whole 4
               for($j = 0; $j < 4; $j++)
               {
                   $character .= strval($splitresult[$i][$j]);
               }
               $ciphertext .= dechex(bindec($character));
           }
       }
       return $ciphertext;
       
   }
   
   // Decryption, the keys are fed in reverse.
   
   function desd($plaintext, $key)
   {// key has to be 64 bits or 8 bytes
       
       $kbyte = substr($key, 0, 8);
       $kblock = bytesbits($kbyte); //store
       
       //$test = array(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,
       //	31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64);
       //	You can use this test to see if the permutation is actually applied correctly, simply change kblock
       //	in the forloop below to test.
       
       // The Key Scheduling starts here
       // ****************************************************************************
       // Permutation for the 64-bit key block before the shiftings.
       $pc1 = array(57, 49, 41, 33, 25, 17, 9,
           1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4);
       $pkey = array(56);
       
       // PC1 Permutation for the key using the pc1 table above.
       for($i = 0; $i < 56; $i++)
       {
           $pkey[$i] = $kblock[$pc1[$i]-1];
       }
       /*
        for($i = 0; $i < 56; $i++)
        {
        echo $pkey[$i]. "<br>"; // Print test for the permutation.
        }*/
       
       $subkeys = array(16); //There will be 16 subkeys, initializing here.
       
       // Shiftings to produce 16 keys that will be permutated again using PC2.
       // The permutation above will be split in half and shifted separately
       // each half is 28-bits, will be stored in leftsub and rightsub temporarily
       // Each level of shifting varies according to the following table.
       $shifts = array(1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1);
       
       $leftsub = array(28); // to hold 28 bits of the left side of the subkey
       $rightsub = array(28);
       
       $leftrightsub = array_chunk($pkey, 28, false); // Chunks/splits the subkeys into two 32 bits.
       // Assign the two halves into left and right accrodingly.
       $leftsub = $leftrightsub[0];
       $rightsub = $leftrightsub[1];
       
       //print_r($leftsub); test print, work fine!
       
       // Do the shifts and concatenate left and right to their corresponding subkeys index.
       
       for($i = 0; $i < 16; $i++) // for the 16 subkeys
       {
           // left side
           for($s = 0; $s < $shifts[$i]; $s++)// Shift amount based on the table above.
           {
               $topbit = $leftsub[0]; // save the msb before shifting.
               for($j = 1; $j < 28; $j++)
               {
                   $leftsub[$j-1] = $leftsub[$j]; // shift one at a time. I know this feels so slow.
               }
               $leftsub[27] = $topbit; // put the top bit into the lsb spot
           }
           
           // right side
           for($s = 0; $s < $shifts[$i]; $s++)// Shift amount based on the table above.
           {
               $topbit = $rightsub[0]; // save the msb before shifting.
               for($j = 1; $j < 28; $j++)
               {
                   $rightsub[$j-1] = $rightsub[$j]; // shift one at a time. I know this feels so slow.
               }
               $rightsub[27] = $topbit; // put the top bit into the lsb spot
           }
           // merge the two sides and store in subkeys.
           $subkeys[$i] = array_merge($leftsub, $rightsub);
       }
       //print_r($subkeys[15]); //tested the result for one of the shifts, look alright
       // The first and last subkey turned out to be the same permutation. interesting...
       
       // Now we need to permute each subkey again, using the following table.
       // Interestingly enough, this permutation further reduces the subkey lenghts
       // from 56-bits to 48-bits, which will match the reduction in the input text later on
       $pc2 = array(14, 17, 11, 24, 1, 5,
           3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8,
           16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32);
       // Similar to the PC1 permutation.
       // PC2 Permutation for the subkeys using the pc2 table above.
       $finalsk = array(16);
       for($s = 0; $s < 16; $s++)// For each subkey, we permute.
       {
           $tempkey = array(48);
           for($i = 0; $i < 48; $i++)
           {
               $tempkey[$i] = $subkeys[$s][$pc2[$i]-1];
           }
           $finalsk[$s] = $tempkey;
       }
       //print_r($finalsk[0]); // I walked through this, the permutation works! Whew.
       // finalsk now holds the keys to be used in the cipher, that took soo much work for key scheduling lol.
       // ****************************************************************************
       // Key Scheduling ends here!
       
       // Now that we have the subkeys ready! We start chunking the input into 64-bit blocks and do 16 rounds of permutations and so forth.
       // Each round will use the corresponding key that was generated earlier. Each 64-bit block will undergo the same process
       // repeating until all the bytes in the text is converted to cipher text. Maybe I should padd the plain text with some A's or something
       // to ensure that the blocks are always 64-bits because I am not sure if the logic stays in tact with size other than 64. Same with the
       // key...
       
       // Initial Permutation of the 64-bit block from the plain text.
       $ip = array(58, 50, 42, 34, 26, 18, 10, 2,
           60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6,
           64, 56, 48, 40, 32, 24, 16, 8,
           57, 49, 41, 33, 25, 17, 9, 1,
           59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5,
           63, 55, 47, 39, 31, 23, 15, 7);
       
       
       $ptlen = strlen($plaintext);
       $numblocks = $ptlen / 8; // There are this many blocks in the plaintext.
       //echo "Number of blocks: $numblocks <br>";
       
       $ciphertext = "";
       for($m = 0; $m < $numblocks; $m++) // Run as much as the number of blocks.
       {
           
           $pbytes = substr($plaintext, ($m * 8), 8); // Get 8 bytes from the plain text.
           //echo "<br> $pbytes <br>";
           $pblock = bytesbits($pbytes);
           //print_r($pblock);
           $ptext = array(64);// Stores the 64-bits of this block from the plain text.
           
           // Permute the block based on the initial permutation table above.
           for($i = 0; $i < 64; $i++)
           {
               $ptext[$i] = $pblock[$ip[$i]-1];
           }
           // $ptext now holds a bit format of an 8-byte(64-bits) of the plaintext and is permuted using the IP table above.
           $leftpt = array(32);
           $rightpt = array(32);
           $leftrightpt = array_chunk($ptext, 32, false);
           
           // Reversed for decryption...
           $leftpt = $leftrightpt[0];
           $rightpt = $leftrightpt[1];
           
           //print_r($leftpt);
           //*************************************************************************************************
           // This is the part that is reversed, instead of starting from the 0th key, we start at the 15th.
           // ************************************************************************************************
           // 16 rounds for the block using the 16 subkeys generated earlier.
           
           for($i = 15; $i >= 0 ; $i--) // 16 rounds
           {
               $lefttemp = $rightpt;
               $erxorkres = erxork($rightpt, $finalsk[$i]);
               $rightside = shrink($erxorkres);
               $righttemp = array(32);
               for($j = 0; $j < 32; $j++) // Left Xor (Expanded Right Xor Key) side for the Right
               {
                   $righttemp[$j] = $leftpt[$j] ^ $rightside[$j];
               }
               $leftpt = $lefttemp;
               $rightpt = $righttemp;
           }
           // Then at the last step, we swap Left and Right, merge, then permute them one last time using IP table.
           $result = array_merge($rightpt, $leftpt);
           
           $ip = array(40, 8, 48, 16, 56, 24, 64, 32,
               39, 7, 47, 15, 55, 23, 63, 31,
               38, 6, 46, 14, 54, 22, 62, 30,
               37, 5, 45, 13, 53, 21, 61, 29,
               36, 4, 44, 12, 52, 20, 60, 28,
               35, 3, 43, 11, 51, 19, 59, 27,
               34, 2, 42, 10, 50, 18, 58, 26,
               33, 1, 41, 9, 49, 17, 57, 25);
           $presult = array(64);
           for($i = 0; $i < 64; $i++)
           {
               $presult[$i] = $result[$ip[$i]-1];
           }
           //print_r($presult);
           // Now we can chunk the presult into 4 bits to save in the cipher text as a character each.
           $splitresult = array_chunk($presult, 4, false); // There are 16 4-bit groups in a 64-bit sequence.
           //echo "<br>";
           //print_r($splitresult);
           
           for($i = 0; $i < 16; $i++)
           {
               $character = "";
               // Consolidate the separate bits into a whole 4
               for($j = 0; $j < 4; $j++)
               {
                   $character .= strval($splitresult[$i][$j]);
               }
               $ciphertext .= dechex(bindec($character));
           }
       }
       return $ciphertext;
       
   }
   
   
   // Expands r and xors with key.
   function erxork($right, $subkey) // expands the right part and XORs with the corresponding subkey.
   {
       $e = array(32, 1, 2, 3, 4, 5,
           4, 5, 6, 7, 8, 9,
           8, 9, 10, 11, 12, 13,
           12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21,
           20, 21, 22, 23, 24, 25,
           24, 25, 26, 27, 28, 29,
           28, 29, 30, 31, 32, 1);
       $eright = array(48); // expanded right.
       for($i = 0; $i < 48; $i++)
       {
           $eright[$i] = $right[$e[$i]-1];
       }
       //print_r($eright); // Checking if it is matching, seems like it.
       
       $erxork = array(48);
       for($i = 0; $i < 48; $i++) // XOR every bit of the expanded right with its corresponding subkey.
       {
           $erxork[$i] = $eright[$i] ^ $subkey[$i];
           //echo $subkey[$i]. " <br>";
       }
       return $erxork;
   }
   // Shrinks the Expanded R XORed with its Key to 32-bits and permutes them using the P table.
   function shrink($erxork)
   {
       $sixbits = array_chunk($erxork, 6, false); // Now chunk the resulting E XOR K into 6 bits groups.
       //print_r($sixbits); // Test print, the E XOR K is split into 6 bit groups, gucci.
       
       // S box
       $sbox = array(32);// 32-bit S block
       $sbc = 0;
       
       // S1 block
       $s1r1 = array(14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7);
       $s1r2 = array(0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8);
       $s1r3 = array(4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0);
       $s1r4 = array(15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13);
       
       $s1 = array($s1r1, $s1r2, $s1r3, $s1r4);
       fourbits($sixbits[0], $s1, $sbox, $sbc);
       
       
       // S2 block
       $s2r1 = array(15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10);
       $s2r2 = array(3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5);
       $s2r3 = array(0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15);
       $s2r4 = array(13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9);
       
       $s2 = array($s2r1, $s2r2, $s2r3, $s2r4);
       fourbits($sixbits[1], $s2, $sbox, $sbc);
       
       // S3 block
       $s3r1 = array(10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8);
       $s3r2 = array(13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1);
       $s3r3 = array(13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7);
       $s3r4 = array(1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12);
       
       $s3 = array($s3r1, $s3r2, $s3r3, $s3r4);
       fourbits($sixbits[2], $s3, $sbox, $sbc);
       
       // S4 block
       $s4r1 = array(7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15);
       $s4r2 = array(13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9);
       $s4r3 = array(10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4);
       $s4r4 = array(3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14);
       
       $s4 = array($s4r1, $s4r2, $s4r3, $s4r4);
       fourbits($sixbits[3], $s4, $sbox, $sbc);
       
       // S5 block
       $s5r1 = array(2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9);
       $s5r2 = array(14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6);
       $s5r3 = array(4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 15, 6, 3, 0, 14);
       $s5r4 = array(11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3);
       
       $s5 = array($s5r1, $s5r2, $s5r3, $s5r4);
       fourbits($sixbits[4], $s5, $sbox, $sbc);
       
       // S6 block
       $s6r1 = array(12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11);
       $s6r2 = array(10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8);
       $s6r3 = array(9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6);
       $s6r4 = array(4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13);
       
       $s6 = array($s6r1, $s6r2, $s6r3, $s6r4);
       fourbits($sixbits[5], $s6, $sbox, $sbc);
       
       // S7 block
       $s7r1 = array(4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1);
       $s7r2 = array(13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6);
       $s7r3 = array(1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2);
       $s7r4 = array(6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12);
       
       $s7 = array($s7r1, $s7r2, $s7r3, $s7r4);
       fourbits($sixbits[6], $s7, $sbox, $sbc);
       
       // S8 block
       $s8r1 = array(13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0 ,12, 7);
       $s8r2 = array(1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2);
       $s8r3 = array(7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8);
       $s8r4 = array(2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11);
       
       $s8 = array($s8r1, $s8r2, $s8r3, $s8r4);
       fourbits($sixbits[7], $s8, $sbox, $sbc);
       
       $perm = array(16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2, 8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25);
       
       $psbox = array(32);
       
       for($i = 0; $i < 32; $i++)
       {
           $psbox[$i] = $sbox[$perm[$i]-1];
       }
       
       return $psbox;
   }
   
   
   // Converts 8 bytes to 64-bits and store them in an array. Will be used for permutations.
   function bytesbits($bytes)
   {
       
       // Initialize a block array to hold 64-bits at a time for processing.
       $block = array(64);
       $bc = 0;// indexing for the $block array.
       for($i = 0; $i < 8; $i++)// runs for each byte, adding each bit format into the block array
       {
           $chunk = decbin(ord($bytes[$i])); // chunk is just 1 byte to avoid confusion.
           $clen = strlen($chunk);// Its necessary to get the length because sometimes
           // the number of bits differ per byte.
           for($p = 0; $p < 8-$clen; $p++)// makes sure to padd with 0 to preserve 8 bit count
           {
               $block[$bc] = 0;
               $bc++;
           }
           for($j = 0; $j < $clen; $j++)// fill the block with the remaining bits
           {
               $block[$bc] = $chunk[$j];
               $bc++;
           }
       }
       return $block;
   }
   // Creates a four bit from the 6-bits in the S blocks. Pretty similar with the method above, with a couple tweaks.
   function fourbits($sixbits, $sblock, &$sbox, &$sbc)
   {
       $sr = bindec(strval($sixbits[0]) . strval($sixbits[5]));
       $sc = bindec(strval($sixbits[1]).strval($sixbits[2]).strval($sixbits[3]).strval($sixbits[4]));
       $bits = decbin($sblock[$sr][$sc]);
       $blen = strlen($bits);// Its necessary to get the length because sometimes
       // the number of bits differ per block.
       for($p = 0; $p < 4-$blen; $p++)// makes sure to padd with 0 to preserve 4 bit count
       {
           $sbox[$sbc] = 0;
           $sbc++;
       }
       for($j = 0; $j < $blen; $j++)// fill the block with the remaining bits
       {
           $sbox[$sbc] = $bits[$j];
           $sbc++;
       }
   }
?>

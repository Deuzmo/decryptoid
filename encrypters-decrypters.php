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
   
   
   // Transposition Cipher, pads with A's for uneven plain texts.
   function transpose($plaintext, $key)
   {
       // Remove all non-letters and capitalize the letters.
       $plaintext = strtoupper(preg_replace('/[^a-zA-Z]/', '', $plaintext));
       $key = strtoupper(preg_replace('/[^a-zA-Z]/', '', $key));
       
       if($key == "")// If the key turned out to be empty, display message and return nothing
       {
           echo "You have entered an invalid key";
           return;
       }
       
       $keylen = strlen($key);
       
       while(strlen($plaintext) % $keylen != 0)
       {
           $plaintext .= "A"; // pad with A's if the length of the input cannot be divided with keylen evenly
       }
       $columnlen = strlen($plaintext) / strlen($key);
       
       
       $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
       $ciphertext = "";
       $a = 0;
       for($i = 0; $i < $keylen; $i++)
       {    // $a was never set previously according to the debugger?
           while($a < 26)
           {
               $letterPos = strpos($key, $alphabet[$a]);
               $a++;
               if($letterPos !== FALSE) // Changed this to check for FALSE instead to be safe.
               { // If strpos didn't give letterPos a letter this break shouldn't run.
                   break;
               }
           }
           for($c = 0; $c < $columnlen; $c++)
           {
               $ciphertext .= $plaintext[$keylen * $c + $letterPos];
           }
       }
       return $ciphertext;
   }
   

   // Decryption for the Transposed ciphertext.
   function detranspose($ciphertext, $key)
   {
       // Remove all non-letters and capitalize the letters.
       $ciphertext = strtoupper(preg_replace('/[^a-zA-Z]/', '', $ciphertext));
       $key = strtoupper(preg_replace('/[^a-zA-Z]/', '', $key));
       
       if($key == "")// If the key turned out to be empty, display message and return nothing
       {
           echo "You have entered an invalid key";
           return;
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
       
       // Individual columns from the cipher text.
       $columns = array($keylen);
       
       for($i = 0; $i < $keylen; $i++)
       {
           $columns[$i] = substr($ciphertext, $columnlen * $i, $columnlen);
       }
       // Rearranged will hold the proper order of the columns before decrypting.
       $rearranged = array($keylen);
       $c = 0;
       $a = 0;
       while($c < $keylen)// We will only loop through the cipher based on key lenght
       {
           $letterPos = strpos($key, $alphabet[$a]);// Position of a letter in the key.
           $a++;// Keep moving through the alphabet.
           if($letterPos >= 0)// We rearrange the columns based on the key
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
   function rivest($text, $key)
   {
       $s = array(256); // Array for bits [0, 255]
       // Initialize the 256 Bits of S
       for($i = 0; $i < 256; $i++)
       {
           $s[$i] = $i;
       }
       
       $keylen = strlen($key);
       $textlen = strlen($text);
       echo "<br> $textlen <br>";
       $k = array(256); // Array to contain the repeated key.
       // Initialize $k with the key, repeating until full.
       for($i = 0; $i < 256; $i++)
       {
           $k[$i] = ord($key[$i % $keylen]); // Cycle through the key, storing each byte into $k
           //echo $k[$i]. "<br>";
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
       for($i = 1; $i < 256; $i++) // This loop discards the first 256 bytes generated.
       {			// but it is usually safer to discard as many bytes as possible
           // as long as the decryption does the same, which in this case, it does.
           // The discarding prevents attacks from related characters. The ciphertext also seem
           // to have cycled completely, avoiding character retentions.
           $j = $j + $s[$i] % 256;
           swap($s[$i], $s[$j]);
       }
       $j = 0;
       for($i = 1; $i < $textlen; $i++)
       {
           $j = $j + $s[$i] %256;
           swap($s[$i], $s[$j]);
           $t = ($s[$i] + $s[$j]) % 256;
           $keystream[$i] = $s[$t];// We store the the generated byte into the keystream.
       }
      
       $ciphered = "";
       for($i = 0; $i < $textlen; $i++)
       {
           $ciphered .= chr($keystream[$i] ^ ord($text[$i]));
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
?>
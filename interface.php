<?php
   // File initializes the database object to query.
   // Contains safe functions to query the database
   // and general interface functions
   //
   // THE VARIABLE $userTable INDICATES THE TABLE WHERE INPUT IS STORED!
   //
   //
   require_once 'login.php';
   $userTable = "Users";
   $inputHist = "InputHistory";

   $conn = new mysqli($hn, $un, $pw, $db);
   if ($conn->connect_error) die("Oops something went wrong!");
   $conn->query("USE $db"); 

   // Clears strings from special characters from the login input
   function sanitizeLogin($conn, $var)
	{
		return htmlentities($conn->real_escape_string($_SERVER[$var]));
   }

   // retrieves sanitized version of the strings stored in the POST array.
   function getPOST($conn, $var)
	{
		return $conn->real_escape_string($_POST[$var]);
   }
   
   // Uses prepare statement for insertions
   function insertUser($conn, $table, $user, $email, $password){
      $safeQuery = $conn->prepare("INSERT INTO $table VALUES(?,?,?,?)");
      $hash = password_hash($password, PASSWORD_DEFAULT); 
      $safeQuery->bind_param("sss", $user, $email, $hash);
      $safeQuery->execute();
      if ($safeQuery->error != "") die("Oops, something went wrong!");
      $safeQuery->close(); 
   }


   // Verifies a login attempt
   function login($conn, $table, $user, $pw){
      $result = $conn->query("SELECT hash FROM $table WHERE username = '$user'"); 
      if ($result->num_rows == 0){
         return false;
      }
      else {
         $rows = $result->fetch_row();
         $storedHash = $rows[0]; 
         return password_verify($pw, $storedHash);
      }
   }

   // IN PROGRESS - Verifies that format for user/email creation
   function verifyFormat($user, $pw){

   $validUser = preg_match("/ /", $user);
   $validPw = preg_match("/ /", $pw);
   
   return ($validUser && $validPw);
   }

   // Auxiliary function. Reads file, sanitizes full file and returns a string 
   // representation
   function getContents($conn, $uploadName){
      
      if ($_FILES[$uploadName]['type'] != "text/plain") die ("error, invalid file");

      $fileName = $_FILES[$uploadName]['tmp_name'];
      $output = "";

      $theFile = fopen($fileName, 'r') or die ("Failed to open file");
      while (!feof($theFile)){
         $line = fgets($theFile);
			$line = str_replace(array("\n", "\r", " "), '', $line);
			$output .= $line;
      }

      $output = $conn->real_escape_string($output);

      if (strlen($output) == 0) die ("error, file is empty");
      
		return $output;
   }
   
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
?>
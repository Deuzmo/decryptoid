<?php
   // File initializes the database object to query.
   // Contains safe functions to query the database
   // and general interface functions
   //
   // THE VARIABLE $userTable/$inputHist indicate where input is stored
   //

   require_once 'login.php';
   $userTable = "users";
   $inputHist = "input_history";

   $conn = new mysqli($hn, $un, $pw, $db);
   if ($conn->connect_error) die("Oops something went wrong!");


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
   
   //Verifies that account creation was attempted
   function attemptedCreation(){
      return (isset($_POST['username']) && 
               isset($_POST['email']) &&
               isset($_POST['pw']) &&
               isset($_POST['pwVerify'])
            );
   }
   
   // Uses prepare statement for insertions, returns true or false depending
   // on success.
   function insertUser($conn, $table, $user, $email, $password)
   {
      $safeQuery = $conn->prepare("INSERT INTO $table VALUES(?,?,?)");
      $hash = password_hash($password, PASSWORD_DEFAULT); 
      $safeQuery->bind_param("sss", $user, $email, $hash);
      $safeQuery->execute();
      if ($safeQuery->error != "") return FALSE;
      $safeQuery->close(); 
      return TRUE;
   }


   // Verifies a login attempt
   function login($conn, $table, $user, $pw)
   {
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


   function uniqueUser($conn, $table, $user){
      $exists = $conn->query("SELECT username from $table WHERE username = '$user'");
      
      if (($exists->num_rows) > 0) return FALSE;
      else return TRUE;
   }
   

   // Verifies the format for a valid username.
   function validUser($user){
      $invalid = preg_match("/[^\w_-]/", $user);
      return !$invalid;
   }

   // Verifies the email formatting at user creation time.
   function validEmail($email){
      if (filter_var($email, FILTER_VALIDATE_EMAIL) != FALSE)
         return TRUE;
      else 
         return FALSE;
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

   // Destroys the session
   function destroy_session_and_data() {
		$_SESSION = array();
		setcookie(session_name(), '', time() - 2592000, '/');
		session_destroy();
	}
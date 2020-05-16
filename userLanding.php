<?php 	// userLanding.php
	require_once 'interface.php';
	session_start();

	
	if (	isset($_SESSION['username']) && 
			$SESSION['check'] == hash('ripemd128', $_SERVER['REMOTE_ADDR'] .
				$_SERVER['HTTP_USER_AGENT']))
	{
		$username = $_SESSION['username'];

		// Session expires in 10 minutes
		ini_set('session.gc_maxlifetime', 60*10);

		echo "<h4>Logged in as '$username' </h4>";
		// Text upload form
		echo <<<_END
		<form style="border-style:ridge; width:25%; padding:20px" action="userLanding.php" method="post" enctype='multipart/form-data'>
		<div style = 'font-weight:bold;'>Enter the encryption key (if needed) and select the file to encrypt/decrypt </div>
		<input type="text" name="Key"> <input style = 'margin:10px' type='file' name='uploadedFile'><br>

		<input type="radio" id="encryption" name="process" value="encrypt" checked>
		<label for="encryption">Encrypt</label><br>

		<input type="radio" id="Decrypt" name="process" value="decrypt">
		<label for="decryption">Decrypt</label><br>

		<input style= "margin-left:40%;" type="submit" value="Process File">
		</form>

_END;

		if (isset($_POST['key']) && file_exists($_FILES['uploadedFile']['tmp_name'])){
		$key = getPOST($conn, 'key');
		$filename = $_FILES['uploadedFile']['tmp_name'];

			// If key field was left empty
			if ($key == ""){
				echo "<h4 style = 'color:orange'>Warning: Empty Key works only for substitution!</h4>";
			}

			$text = getContents($conn, $filename);

			/************************************************************************************* */
			// Text is the text to cypher/decypher, proceed from here to show the output
			/************************************************************************************ */

		}
	}

	else {
		die("Restricted section. <b><a href=guestLanding.php>Please click here</a></b>" . 
		" to log in or create a new account.");
	}
?>

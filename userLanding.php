<?php 	// userLanding.php
	require_once 'interface.php';
	session_start();

	
	if (	isset($_SESSION['username']) && 
			$_SESSION['check'] == hash('ripemd128', $_SERVER['REMOTE_ADDR'] .
				$_SERVER['HTTP_USER_AGENT']))
	{
		$username = $_SESSION['username'];

		// Session expires in 10 minutes
		ini_set('session.gc_maxlifetime', 60*10);
		
		// Text upload form
		echo <<<_END
		<div style = "border-style:ridge; width:40%; padding:20px; margin: 0 auto">
			<h4 style = "color:blue; margin:0; text-align: center;">Logged in as '$username' </h4>
			
			<form style="width:100%; padding:20px" action="userLanding.php" method="post" enctype='multipart/form-data'>
				<div style = "font-weight:bold; margin: 20 auto;">Select the encryption method and provide the key if necessary.</div>
				
				<label for="method" style= "display: inline-block; margin-top: 30px;">Encryption algorithm:</label>
				<select name="method">
					<option value="substitution">Substitution</option>
					<option value="doubleTrans">Double Transposition</option>
					<option value="rc4">RC4</option>
					<option value="des">DES</option>
				</select>
				<br>
				<div style = "display: inline-block; margin-top: 30px; font-style: italic;">Key:
					<input type="text" name="Key"><br>
				</div>
				<div style = "margin-top: 30px; font-style:italic">Text file:
					<input style = "margin-bottom: 30px;" type='file' name='uploadedFile' accept=".txt">
				</div>
				
				<input type="radio" id="encryption" name="process" value="encrypt" checked>
				<label for="encryption">Encrypt</label><br>
				
				<input type="radio" id="Decrypt" name="process" value="decrypt">
				<label for="decryption">Decrypt</label><br>
				
				<input style= "display: block; margin: 0 auto;" type="submit" value="Process File">
			</form>
		</div>
		

_END;

		if (isset($_POST['key']) && isset($_POST['method']) && file_exists($_FILES['uploadedFile']['tmp_name'])){
			echo "<div style = \"border-style:ridge; width:40%; padding:20px; margin: 0 auto\">";
			$key = getPOST($conn, 'key');
			$method = getPost($conn, 'method');
			$filename = $_FILES['uploadedFile']['tmp_name'];

			// If key field was left empty
			if ($key == ""){
				echo "<h4 style = 'color:orange'>Warning: Empty Key works only for substitution!</h4>";
			}

			$text = getContents($conn, $filename);

			/************************************************************************************* */
			// Text is the text to cypher/decypher, proceed from here to show the output
			/************************************************************************************ */
		echo "</div>"; // Closes style div
		}
	}

	else {
		die("Restricted section. <b><a href=guestLanding.php>Please click here</a></b>" . 
		" to log in or create a new account.");
	}
?>

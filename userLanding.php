<?php 	// userLanding.php
	require_once 'interface.php';
	require_once 'encrypters-decrypters.php';
	session_start();

	
	if (	isset($_SESSION['username']) && $_SESSION['check'] == 
			hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']))
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
					<input type="text" name="key"><br>
				</div>
				<div style = "margin-top: 30px; font-style:italic">Text file:
					<input style = "margin-bottom: 30px;" type="file" name="uploadedFile">
				</div>
				
				<input type="radio" id="encryption" name="process" value="encrypt" checked>
				<label for="encryption">Encrypt</label><br>
				
				<input type="radio" id="decryption" name="process" value="decrypt">
				<label for="decryption">Decrypt</label><br>
				
				<input style= "display: block; margin: 0 auto;" type="submit" value="Process File">
			</form>
		</div>
		

_END;

		if (isset($_POST['method']) && file_exists($_FILES['uploadedFile']['tmp_name'])){
			echo "<div style = \"border-style:ridge; width:40%; padding:20px; margin: 0 auto\">";

			$key = isset($_POST['key']) ? getPOST($conn, 'key') : "";
			$method = getPOST($conn, 'method');
			$process = getPOST($conn, 'process');
			$text = getContents($conn, 'uploadedFile');
			$output = "";

			// If key field was left empty
			if ($key == "" && $method != "substitution"){
				$output = "<h4 style = 'color:orange'>Warning: Empty Key works only for substitution!</h4>";
			}
			else{
				// Keeps track of the user inputs, provided it's not invalid
				// (e.g empty key with rc4 algorithm would make no sense)
				insertInfo($conn, $inputHist, $username, $text, $method);
			}
	
			if ($method == "substitution"){
				
				if ($process == "encrypt"){
					$output = simpleSub($text, TRUE);
				}
				else{
					$output = simpleSub($text, FALSE);
				}

			}
			else if ($method == "doubleTrans" && $key != ""){

				if ($process == "encrypt"){
					$output = transpose($text, $key);
				}
				else{
					$output = detranspose($text, $key);
				}

			}
			else if ($method == "rc4" && $key != ""){
				if($process == "encrypt"){
					
					$output = rivest($text, $key, 1);
				}
				else{
					$output = rivest($text, $key, 0);
				}

			}
			else if ($method == "des" && $key != ""){

				if ($process == "encrypt"){
					$output = des($text, $key);
				}
				else{
					$output = "Feature not working yet!";
				}

			}
			$conn->close();
			echo "<h3 style = 'color:blue;'>The resulting output is:</h3>" .
				"$output";

			echo "</div>"; // Closes style div
		}
	}

	else {
		$conn->close();
		die("Restricted section. <b><a href=guestLanding.php>Please click here</a></b>" . 
		" to log in or create a new account.");
	}
?>

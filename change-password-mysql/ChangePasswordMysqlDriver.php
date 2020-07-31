<?php

class ChangePasswordMysqlDriver implements \RainLoop\Providers\ChangePassword\ChangePasswordInterface
{
	/**
	 * @var string
	 */
	private $mHost = '127.0.0.1';

	/**
	 * @var string
	 */
	private $mUser = '';

	/**
	 * @var string
	 */
	private $mPass = '';

	/**
	 * @var string
	 */
	private $mDatabase = '';

	/**
	 * @var string
	 */
	private $mTable = '';

	/**
	 * @var string
	 */
	private $mColumn = '';

	/** 
	 * @var string
	 */
	private $uColumn = '';
	
	/**
	 * @var string
	 */
	private $cryptScheme = 'CRAM-MD5';
	
	/**
	 * @var string
	 */
	private $doveadmBin = '/usr/bin/doveadm';

	/**
	 * @var \MailSo\Log\Logger
	 */
	private $oLogger = null;

	/**
	 * @var array
	 */
	private $aDomains = array();

	/**
	 * @param string $mHost
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetmHost($mHost)
	{
		$this->mHost = $mHost;
		return $this;
	}

	/**
	 * @param string $mUser
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetmUser($mUser)
	{
		$this->mUser = $mUser;
		return $this;
	}

	/**
	 * @param string $mPass
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetmPass($mPass)
	{
		$this->mPass = $mPass;
		return $this;
	}

	/**
	 * @param string $mDatabase
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetmDatabase($mDatabase)
	{
		$this->mDatabase = $mDatabase;
		return $this;
	}

	/**
	 * @param string $mTable
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetmTable($mTable)
	{
		$this->mTable = $mTable;
		return $this;
	}

	/**
	 * @param string $mColumn
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetmColumn($mColumn)
	{
		$this->mColumn = $mColumn;
		return $this;
	}

	/**
	 * @param string $uColumn
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetuColumn($uColumn)
	{
		$this->uColumn = $uColumn;
		return $this;
	}
	
	/**
	 * @param string $cryptScheme
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetCryptScheme($cryptScheme)
	{
	    $this->cryptScheme = $cryptScheme;
	    return $this;
	}
	
	/**
	 * @param string $doveadmBin
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetDoveadmBin($doveadmBin)
	{
	    $this->doveadmBin = $doveadmBin;
	    return $this;
	}

	/**
	 * @param \MailSo\Log\Logger $oLogger
	 *
	 * @return \ChangePasswordMysqlDriver
	 */
	public function SetLogger($oLogger)
	{
		if ($oLogger instanceof \MailSo\Log\Logger)
		{
			$this->oLogger = $oLogger;
		}

		return $this;
	}
	
	/**
	 * @param array $aDomains
	 *
	 * @return bool
	 */
	public function SetAllowedDomains($aDomains)
	{
		if (\is_array($aDomains) && 0 < \count($aDomains))
		{
			$this->aDomains = $aDomains;
		}

		return $this;
	}
	
	/**
	 * @param \RainLoop\Account $oAccount
	 *
	 * @return bool
	 */
	public function PasswordChangePossibility($oAccount)
	{
		return $oAccount && $oAccount->Domain() &&
			\in_array(\strtolower($oAccount->Domain()->Name()), $this->aDomains);
	}

	/**
	 * @param \RainLoop\Account $oAccount
	 * @param string $sPrevPassword
	 * @param string $sNewPassword
	 *
	 * @return bool
	 */
	public function ChangePassword(\RainLoop\Account $oAccount, $sPrevPassword, $sNewPassword)
	{
		if ($this->oLogger)
		{
			$this->oLogger->Write('Try to change password for '.$oAccount->Email());
		}

		$bResult = false;

		$dsn = 'mysql:host='.$this->mHost.';dbname='.$this->mDatabase.';charset=utf8';
		$options = array(
			PDO::ATTR_EMULATE_PREPARES  => false,
			PDO::ATTR_PERSISTENT        => true,
			PDO::ATTR_ERRMODE           => PDO::ERRMODE_EXCEPTION
		);

		try
		{
			$conn = new PDO($dsn,$this->mUser,$this->mPass,$options);
			$select = $conn->prepare("SELECT $this->mColumn FROM $this->mTable WHERE $this->uColumn = :id LIMIT 1");
			$select->execute(array(
				':id'     => $oAccount->Email()
			));
			
			$colCrypt = $select->fetchAll(PDO::FETCH_ASSOC);
			$sCryptPass = $colCrypt[0][$this->mColumn];
			
			$sPrevPasswordCrypt = ($this->cryptScheme == 'plain' || $this->cryptScheme == '') ?
			         $sCryptPass :
			         rtrim(shell_exec(escapeshellcmd($this->doveadmBin." pw -s $this->cryptScheme -p ".escapeshellarg($sPrevPassword))));
			
	        $oldPassOK = 0 < strlen($sCryptPass) && $sPrevPasswordCrypt === $sCryptPass;
            //$this->oLogger->write('Old password: '.($oldPassOK ? "matches" : "mismatch or failed to read from DB"));
	        $newPassOK = 7 < mb_strlen($sNewPassword); // && !preg_match('/[^A-Za-z0-9]+/', $sNewPassword);
	        //$this->oLogger->write('New password: '.($newPassOK ? 'acceptable' : 'failed'));
			
	        if ($oldPassOK && $newPassOK)
			{
				$update = $conn->prepare("UPDATE $this->mTable SET $this->mColumn = :crypt WHERE $this->uColumn = :id");
				$sNewPasswordCrypt  = ($this->cryptScheme == 'plain' || $this->cryptScheme == '') ?
				        $sNewPassword :
				        rtrim(shell_exec(escapeshellcmd($this->doveadmBin. " pw -s $this->cryptScheme -p ".escapeshellarg($sNewPassword))));
				$update->execute(array(
					':id'    => $oAccount->Email(),
				    ':crypt' => $sNewPasswordCrypt
				));


				$bResult = true;
 				if ($this->oLogger)
                                {
                                        $this->oLogger->Write('Success! Password changed.');
                                }
			}
			else
			{
				$bResult = false;
				if ($this->oLogger)
                		{
                        		$this->oLogger->Write('Something went wrong. Either current password is incorrect, or new password does not match criteria.');
                		}
			}

		}
		catch (\Exception $oException)
		{
			$bResult = false;
			if ($this->oLogger)
			{
				$this->oLogger->WriteException($oException);
			}
		}

		return $bResult;
	}
}

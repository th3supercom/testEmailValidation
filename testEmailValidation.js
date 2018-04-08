/*jslint node: true, sloppy: true, white: true */

/*
 * testEmailValidation.php
 *
 * @(#) $Id: testEmailValidation.js,v 1.4 2014/04/05 12:10:27 mlemos Exp $
 *
 */

var email, validation, emailValidation;

if(process.argv.length < 3)
{
	console.log('It was not specified the e-mail address for validation.');
}
else
{
	/*
	 * Load the e-mail validation module
	 */
	emailValidation = require('./emailValidation');

	/*
	 * Configure the path of the sockets module
	 */
	emailValidation.socketsModule = './sockets';

	var validation = new emailValidation.validation();
	
	/*
	 * E-mail address of local user to simulate e-mail delivery
	 */
	validation.localAddress = 'localuser@localhost';

	/*
	 * Output debug information
	 */
	validation.debug = true;

	/*
	 * Output debug information about network socket communication
	 */
	validation.debugSockets = false;

	/*
	 * Function to output debug information
	 */
	validation.debugOutput = console.log;

	/*
	 * Timeout for network socket communication in seconds
	 */
	validation.timeout = 15;

	var email = process.argv[2];
	validation.emailDomainsWhitelistFile = 'emaildomainswhitelist.csv';
	validation.invalidEmailUsersFile = 'invalidemailusers.csv';
	validation.invalidEmailDomainsFile = 'invalidemaildomains.csv';
	validation.invalidEmailServersFile = 'invalidemailservers.csv';
	validation.validate(email, function (result)
	{
		if(result.valid === undefined)
		{
			console.log('Error: ' + result.error);
		}
		else
		{
			if(result.valid === null)
			{
				console.log('It was not possible to determine whether the address ' + email + ' is valid' + (result.error ? ': ' + result.error : '.'));
			}
			else
			{
				console.log('The address ' + email + ' is ' + (result.valid ? 'valid' : 'invalid') + '.');
				if(!result.valid && result.status === validation.EMAIL_VALIDATION_STATUS_TYPO_IN_DOMAIN)
				{
					console.log('It may be a typing mistake. The correct email address may be ' + result.suggestions[0] + ' .');
				}
			}
		}
	});
}

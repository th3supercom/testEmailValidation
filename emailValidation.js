/*jslint node: true, plusplus: true, sloppy: true, white: true */

/*
 * emailValidation.php
 *
 * @(#) $Id: emailValidation.js,v 1.8 2014/04/08 09:24:50 mlemos Exp $
 *
 */

exports.socketsModule = 'sockets';

exports.validation = function()
{
	var dns = require('dns'),
		fs = require('fs'),
		sockets = require(exports.socketsModule),
		lastCode = '',

	outputDebug = function(o, message)
	{
		if(o.debug)
		{
			o.debugOutput(message);
		}
	},

	splitAddress = function(email)
	{
		var at = email.indexOf('@');
		if(at === -1)
		{
			at = email.length;
		}
		return { user: email.substr(0, at), domain: email.substr(at + 1) };
	},

	loadCSVFile = function(fileName, result)
	{
		var csv, lines, columns, entries, line;

		if(fileName.length === 0)
		{
			result.error = 'the name of the CSV file is empty';
			return false;
		}
		try
		{
			csv = fs.readFileSync(fileName, { encoding: 'ascii'} );
		}
		catch(e)
		{
			result.error = 'could not read file "' + fileName + '": ' + e.message;
			return false;
		}
		lines = csv.split(/[\r\n|\r|\n]/);
		entries = [];
		for(line = 0; line < lines.length; ++line)
		{
			columns = lines[line].split(/,/);
			if(columns[0].length)
			{
				entries[entries.length] = columns;
			}
		}
		result.entries = entries;
		return true;
	},

	validateDomainWhitelist = function(o, email)
	{
		var result, address, domain, d;

		if(!o.invalidEmailUsers)
		{
			if(o.emailDomainsWhitelistFile.length === 0)
			{
				outputDebug(o, 'The email domains whitelist file was not specified.');  
				return { valid: false };
			}
			outputDebug(o, 'Loading the list of email domains whitelist from ' +  o.emailDomainsWhitelistFile + '...');
			result = {};
			if(!loadCSVFile(o.emailDomainsWhitelistFile, result))
			{
				return { error: result.error };
			}
			o.emailDomainsWhitelist = result.entries;
		}
		address = splitAddress(email);
		for(d = 0; d < o.emailDomainsWhitelist.length; ++d)
		{
			domain = o.emailDomainsWhitelist[d];
			if(address.domain.indexOf(domain[0].toLowerCase()) !== -1)
			{
				outputDebug(o, 'email domain ' + address.user + ' is valid because it contains the text "' + domain[0] + '"');
				return { valid: true };
			}
		}
		return { valid: false };
	},

	validateUserBlacklist = function(o, email)
	{
		var result, address, user, d;

		if(o.invalidEmailUsersFile.length === 0)
		{
			outputDebug(o, 'The email users blacklist file was not specified.');  
			return { valid: true };
		}
		if(!o.invalidEmailUsers)
		{
			outputDebug(o, 'Loading the list of invalid email users from ' +  o.invalidEmailUsersFile + '...');
			result = {};
			if(!loadCSVFile(o.invalidEmailUsersFile, result))
			{
				return { error: result.error };
			}
			o.invalidEmailUsers = result.entries;
		}
		address = splitAddress(email);
		for(d = 0; d < o.invalidEmailUsers.length; ++d)
		{
			user = o.invalidEmailUsers[d];
			if(address.user.indexOf(user[0].toLowerCase()) !== -1)
			{
				outputDebug(o, 'email user ' + address.user + ' is invalid because it contains the text "' + user[0] + '"');
				return { valid: false, status: o.VALIDATION_STATUS_BANNED_WORDS_IN_USER };
			}
		}
		return { valid: true, status: o.EMAIL_VALIDATION_STATUS_OK };
	},

	validateDomainBlacklist = function(o, email)
	{
		var valid = true, result = {}, address, domain, entries, match, check, d, message;

		if(o.invalidEmailDomainsFile.length === 0)
		{
			outputDebug(o, 'The email domains blacklist file was not specified.');  
			return { valid: true };
		}
		if(!o.invalidEmailDomains)
		{
			outputDebug(o, 'Loading the list of invalid email domains from ' +  o.invalidEmailDomainsFile + '...');
			if(!loadCSVFile(o.invalidEmailDomainsFile, result))
			{
				return { error: result.error };
			}
			o.invalidEmailDomains = result.entries;
		}
		address = splitAddress(email);
	invalid:
		for(;;)
		{
			for(d = 0; d < o.invalidEmailDomains.length; ++d)
			{
				domain = o.invalidEmailDomains[d];
				entries = domain.length;
				match = domain[0].toLowerCase();
				if(entries !== 3 && entries !== 4)
				{
					outputDebug(o, 'domain entry for ' + match + ' is incorrectly defined');
					check = 'part';
				}
				else
				{
					check = domain[2];
				}
				switch(check)
				{
					case '':
						if(match === address.domain || '.' + match === address.domain.substr(address.domain.length - match.length - 1, match.length + 1))
						{
							outputDebug(o, 'email domain ' + address.domain + ' is invalid because it contains "' + match + '"');
							valid = false;
							break invalid;
						}
						break;
					default:
						outputDebug(o, check + ' is not a valid check type for domain entry for ' + match);
					case 'part':
						if(address.domain.indexOf(match) != -1)
						{
							valid = false;
							break invalid;
						}
				}
			}
			break;
		}
		result = { valid: valid, status: o.EMAIL_VALIDATION_STATUS_OK };
		if(!valid)
		{
			switch(domain[1])
			{
				case 'fake':
					message = address.domain + ' is a fake email domain';
					result.status = o.EMAIL_VALIDATION_STATUS_FAKE_DOMAIN;
					break;
				case 'typo':
					var fix = domain[3];
					message = address.domain + ' email domain has a typo, it may be ' + fix;
					result.suggestions = [ address.user + '@' + fix];
					result.status = o.EMAIL_VALIDATION_STATUS_TYPO_IN_DOMAIN;
					break;
				case 'disposable':
					message = address.domain + ' is a disposable email domain';
					result.status = o.EMAIL_VALIDATION_STATUS_DISPOSABLE_ADDRESS;
					break;
				case 'temporary':
					message = address.domain + ' is a temporary domain';
					result.status = o.EMAIL_VALIDATION_STATUS_TEMPORARY_DOMAIN;
					break;
				case 'spam trap':
					message = address.domain + ' is a spam trap domain';
					result.status = o.EMAIL_VALIDATION_STATUS_SPAM_TRAP_ADDRESS;
					break;
				case '':
					message = 'email domain ' + address.domain + ' ends in ' + match;
					result.status = o.EMAIL_VALIDATION_STATUS_BANNED_DOMAIN;
					break;
			}
			outputDebug(o, message);
		}
		return result;
	},

	verifyResultLines = function(o, socket, code, callback)
	{
		var lineCallback = function(err, line)
		{
			var c;

			if(err !== null)
			{
				callback(err, -1);
			}
			else
			{
				outputDebug(o, 'S ' + line);
				for(c = 0; c < line.length; ++c)
				{
					if(line[c] === ' ' || line[c] === '-')
					{
						break;
					}
				}
				lastCode = line.substr(0, c);
				if(code !== lastCode)
				{
					callback(null, 0);
				}
				else
				{
					if(c < line.length && line[c] === ' ')
					{
						callback(null, 1);
					}
					else
					{
						socket.readLine(lineCallback);
					}
				}
			}
		};
		socket.readLine(lineCallback);
	},

	validateMx = function(o, addresses, address, email, callback)
	{
		var socket, mx, next = function(err, fatal)
		{
			if(err !== null)
			{
				outputDebug(o, 'Error: ' + err);
			}
			socket.end();
			if(fatal)
			{
				callback({ valid: null, error: err.toString() });
				return true;
			}
			validateMx(o, addresses, address + 1, email, callback);
			return false;
		},
		resolved = function(err, ip, family)
		{
			if(err !== null)
			{
				return next(err, true);
			}
			outputDebug(o, 'Connecting to ' + ip + '...');
			socket.connect(25, ip, function(err)
			{
				if(err !== null)
				{
					return next(err, false);
				}
				outputDebug(o, 'Connected.');
				verifyResultLines(o, socket, '220', function(err, result)
				{
					var localAddress, line;

					if(err !== null)
					{
						return next(err, true);
					}
					if(result <= 0)
					{
						return next(null, false);
					}
					localAddress = splitAddress(o.localAddress);
					line = 'HELO ' + localAddress.domain;
					outputDebug(o, 'C ' + line);
					socket.writeLine(line, function(err)
					{
						if(err !== null)
						{
							return next(err, true);
						}
						verifyResultLines(o, socket, '250', function(err, result)
						{
							if(err !== null)
							{
								return next(err, true);
							}
							if(result <= 0)
							{
								return next(null, false);
							}
							line = 'MAIL FROM: <' + o.localAddress + '>';
							outputDebug(o, 'C ' + line);
							socket.writeLine(line, function(err)
							{
								if(err !== null)
								{
									return next(err, true);
								}
								verifyResultLines(o, socket, '250', function(err, result)
								{
									if(err !== null)
									{
										return next(err, true);
									}
									if(result <= 0)
									{
										return next(null, false);
									}
									line = 'RCPT TO: <' + email + '>';
									outputDebug(o, 'C ' + line);
									socket.writeLine(line, function(err)
									{
										if(err !== null)
										{
											return next(err, true);
										}
										verifyResultLines(o, socket, '250', function(err, result)
										{
											var verifyTemporaryRejection = function(err, result)
											{
												if(err !== null)
												{
													return next(err, true);
												}
												if(!result && lastCode.length && lastCode[0] === '4')
												{
													result = -1;
												}
												var valid = (result ? (result > 0 ? true : null) : false);
												outputDebug(o, 'This host states that the address ' +  email + ' is ' + (valid === null ? 'undetermined' : (valid ? 'valid' : 'invalid') + '.'));
												socket.end();
												outputDebug(o, 'Disconnected');
												callback({ valid: valid });
											};

											if(err !== null)
											{
												return next(err, true);
											}
											if(result)
											{
												line = 'DATA';
												outputDebug(o, 'C ' + line);
												socket.writeLine(line, function(err)
												{
													if(err !== null)
													{
														return next(err, true);
													}
													verifyResultLines(o, socket, '354', verifyTemporaryRejection);
												});
											}
											else
											{
												verifyTemporaryRejection(err, result);
											}
										});
									});
								});
							});
						});
					});
				});
			});
		};

		if(address >= addresses.length)
		{
			callback({ valid: null, status: EMAIL_VALIDATION_STATUS_TEMPORARY_SMTP_REJECTION });
		}
		else
		{
			socket = new sockets.socket();
			socket.debug = o.debugSockets;
			socket.debugOutput = o.debugOutput;
			socket.timeout = o.timeout;
			mx = addresses[address].exchange;
			if(new RegExp('^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$').test(mx))
			{
				resolved(null, mx, 4);
			}
			else
			{
				outputDebug(o, 'Looking up the IP address of ' + mx + ' ...');
				dns.lookup(addresses[address].exchange, 4, resolved);
			}
		}
	},

	validateEmailServers = function(o, servers, callback)
	{
		var result = {}, ipPattern,
		resolveServers = function(servers, server, callback)
		{
			var mx;

			if(server >= servers.length)
			{
				callback();
			}
			else
			{
				mx = servers[server];
				outputDebug(o, 'Looking up the IP address of ' + mx + ' ...');
				dns.lookup(mx, 4, function(err, ip, family)
				{
					var s;

					if(err === null)
					{
						for(s = 0; s < servers.length; ++s)
						{
							if(servers[s] === ip)
							{
								break;
							}
						}
						if(s === servers.length)
						{
							servers[servers.length] = ip;
							outputDebug(o, 'Looking up the host name of ' + ip + ' ...');
							dns.reverse(ip, function(err, domains)
							{
								var d;

								if(err === null)
								{
									for(d = 0; d < domains.length; ++d)
										servers[servers.length] = domains[d];
								}
								resolveServers(servers, server + 1, callback);
							}
							);
						}
						else
						{
							resolveServers(servers, server + 1, callback);
						}
					}
					else
					{
						resolveServers(servers, server + 1, callback);
					}
				});
			}
		};

		if(o.invalidEmailServersFile.length === 0)
		{
			outputDebug(o, 'The email servers blacklist file was not specified.');
			callback({ valid: true });
			return;
		}
		if(!o.invalidEmailServers)
		{
			outputDebug(o, 'Loading the list of invalid email servers from ' +  o.invalidEmailServersFile + '...');
			if(!loadCSVFile(o.invalidEmailServersFile, result))
			{
				callback({ error: result.error });
				return;
			}
			o.invalidEmailServers = result.entries;
		}
		ipPattern = new RegExp('^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$');
		outputDebug(o, 'Resolving email server domains and reverse IP addresses...');
		resolveServers(servers, 0, function()
		{
			var validateServer = function(servers, server)
			{
				var address, i, match, invalid,
				validateInvalidEmailServer = function(i, callback)
				{
					var check;

					if(i === o.invalidEmailServers.length)
					{
						callback({ valid: true, status: o.EMAIL_VALIDATION_STATUS_OK });
						return;
					}
					invalid = o.invalidEmailServers[i];
					match = invalid[0].toLowerCase();
					if(invalid.length !== 3)
					{
						outputDebug(o, 'server entry for ' + match + ' is incorrectly defined');
						check = 'part';
					}
					else
					{
						check = invalid[2];
					}
					switch(check)
					{
						case '':
							if(!ipPattern.test(address) && (match === address || '.' + match === address.substr(address.length - match.length - 1, match.length + 1)))
							{
								outputDebug(o, 'email server is invalid because it ends in ' +  match);
								callback({ valid: false, status: o.EMAIL_VALIDATION_STATUS_BANNED_SERVER_DOMAIN });
								return;
							}
							break;
						case 'ip':
							if(ipPattern.test(address) && match === address)
							{
								outputDebug(o, 'email server is invalid because its IP address is ' + match);
								callback({ valid: false, status: o.EMAIL_VALIDATION_STATUS_BANNED_SERVER_IP });
								return;
							}
							break;
						case 'resolve':
							if(!ipPattern.test(address) && match === address)
							{
								outputDebug(o, 'email server is invalid because it resolves to ' + match);
								callback({ valid: false, status: o.EMAIL_VALIDATION_STATUS_BANNED_SERVER_REVERSE_IP });
								return;
							}
							break;
						default:
							outputDebug(o, check + ' is an invalid check for server server for ' + match);
						case 'part':
							if(address.indexOf(match) !== -1)
							{
								outputDebug(o, 'email server is invalid because it contains ' +  match);
								callback({ valid: false, status: o.EMAIL_VALIDATION_STATUS_BANNED_SERVER_DOMAIN });
								return;
							}
							break;
					}
					validateInvalidEmailServer(i + 1, callback);
				};

				if(server === servers.length)
				{
					callback({ valid: true, status: o.EMAIL_VALIDATION_STATUS_OK });
					return;
				}
				address = servers[server].toLowerCase();
				validateInvalidEmailServer(0, function(result)
				{
					if(!result.valid)
						callback(result);
					else
						validateServer(servers, server + 1);
				});
			};

			validateServer(servers, 0);
		});
	},

	validateEmailDelivery = function(o, email, callback)
	{
		var address;

		address = splitAddress(email);
		outputDebug(o, 'Resolving the domain MX addresses for domain ' + address.domain + ' ...');
		dns.resolveMx(address.domain, function(err, addresses)
		{
			var servers, server;

			if(err !== null)
			{
				outputDebug(o, 'No MX records available. Falling back to the A record of domain ' + address.domain + ' ...');
				addresses = [{ priority: 0, exchange: address.domain}];
			}
			addresses.sort(function(a, b)
			{
				return a.priority === b.priority ? 0 : (a.priority < b.priority ? -1 : 1);
			});
			servers = [];
			for(server = 0; server < addresses.length; ++server)
				servers[server] = addresses[server].exchange;
			validateEmailServers(o, servers, function(result)
			{
				if(!result.valid)
				{
					callback(result);
				}
				else
				{
					validateMx(o, addresses, 0, email, callback);
				}
			});
		});
	};

	this.emailDomainsWhitelist = null;
	this.invalidEmailDomains = null;
	this.invalidEmailUsers = null;
	this.invalidEmailServers = null;

	this.debug = false;
	this.debugSockets = false;
	this.debugOutput = console.log;
	this.timeout = 0;
	this.addressPattern = '^([-!#$%&\'*+./0-9=?A-Z^_`a-z{|}~])+@([-!#$%&\'*+/0-9=?A-Z^_`a-z{|}~]+\\.)+[a-zA-Z]{2,6}$';
	this.localAddress = 'localuser@localhost';
	this.emailDomainsWhitelistFile = '';
	this.invalidEmailUsersFile = '';
	this.invalidEmailDomainsFile = '';
	this.invalidEmailServersFile = '';
	this.EMAIL_VALIDATION_STATUS_OK                       =  0;

	this.EMAIL_VALIDATION_STATUS_TEMPORARY_SMTP_REJECTION = -1;
	this.EMAIL_VALIDATION_STATUS_SMTP_DIALOG_REJECTION    = -2;
	this.EMAIL_VALIDATION_STATUS_SMTP_CONNECTION_FAILED   = -3;

	this.EMAIL_VALIDATION_STATUS_BANNED_WORDS_IN_USER     =  1;
	this.EMAIL_VALIDATION_STATUS_BANNED_DOMAIN            =  2;
	this.EMAIL_VALIDATION_STATUS_FAKE_DOMAIN              =  3;
	this.EMAIL_VALIDATION_STATUS_TYPO_IN_DOMAIN           =  4;
	this.EMAIL_VALIDATION_STATUS_DISPOSABLE_ADDRESS       =  5;
	this.EMAIL_VALIDATION_STATUS_TEMPORARY_DOMAIN         =  6;
	this.EMAIL_VALIDATION_STATUS_SPAM_TRAP_ADDRESS        =  7;
	this.EMAIL_VALIDATION_STATUS_BANNED_SERVER_DOMAIN     =  8;
	this.EMAIL_VALIDATION_STATUS_BANNED_SERVER_IP         =  9;
	this.EMAIL_VALIDATION_STATUS_BANNED_SERVER_REVERSE_IP = 10;

	this.validate = function(email, callback)
	{
		var o = this, pattern, result;

		outputDebug(o, 'Validating the address pattern...');
		pattern = new RegExp(this.addressPattern, 'i');
		if(pattern.test(email))
		{
			outputDebug(o, 'Validating the address domain with a whitelist...');
			result = validateDomainWhitelist(o, email);
			if(result.valid === undefined || result.valid)
			{
				callback(result);
			}
			else
			{
				outputDebug(o, 'Validating the address user against a blacklist...');
				result = validateUserBlacklist(o, email);
				if(result.valid)
				{
					outputDebug(o, 'Validating the address domain against a blacklist...');
					result = validateDomainBlacklist(o, email);
					if(result.valid)
					{
						outputDebug(o, 'Validating the address domain simulating a email delivery...');
						validateEmailDelivery(o, email, callback);
					}
					else
					{
						callback(result);
					}
				}
				else
				{
					callback(result);
				}
			}
		}
		else
		{
			callback({ valid: false, error: 'the address format is invalid' });
		}
		return true;
	};
};
package ocs

var publicLinkTemplate string = `
<!DOCTYPE html>
<html class="ng-csp" data-placeholder-focus="false" lang="en" >
	<head>
		<meta charset="utf-8">
		<title> ownCloud</title>
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="referrer" content="never">
		<meta name="viewport" content="width=device-width, minimum-scale=1.0, maximum-scale=1.0">
		<meta name="theme-color" content="#1d2d44">

		<link rel="icon" href="/core/img/favicon.ico">
		<link rel="apple-touch-icon-precomposed" href="/core/img/favicon-touch.png">
		<link rel="mask-icon" sizes="any" href="/core/img/favicon-mask.svg" color="#1d2d44">
		<link rel="stylesheet" href="/core/css/styles.css">
		<link rel="stylesheet" href="/core/css/inputs.css">
		<link rel="stylesheet" href="/core/css/header.css">
		<link rel="stylesheet" href="/core/css/icons.css">
		<link rel="stylesheet" href="/core/css/fonts.css">
		<link rel="stylesheet" href="/core/css/apps.css">
		<link rel="stylesheet" href="/core/css/global.css">
		<link rel="stylesheet" href="/core/css/fixes.css">
		<link rel="stylesheet" href="/core/css/multiselect.css">
		<link rel="stylesheet" href="/core/css/mobile.css">
		<link rel="stylesheet" href="/core/vendor/select2/select2.css">
		<link rel="stylesheet" href="/core/vendor/jquery-ui/themes/base/jquery-ui.css">
		<link rel="stylesheet" href="/core/css/jquery-ui-fixes.css">
		<link rel="stylesheet" href="/core/css/tooltip.css">
		<link rel="stylesheet" href="/core/css/share.css">
		<link rel="stylesheet" href="/apps/files_versions/css/versions.css">
		<link rel="stylesheet" href="/core/css/jquery.ocdialog.css">
		<link rel="stylesheet" href="/apps/files_sharing/css/public.css">
		<link rel="stylesheet" href="/apps/files_sharing/css/mobile.css">
		<link rel="stylesheet" href="/apps/files/css/files.css">
		<link rel="stylesheet" href="/apps/files/css/upload.css">

		<script src="/index.php/core/js/oc.js"></script>
		<script src="/core/vendor/jquery/dist/jquery.min.js"></script>
		<script src="/core/vendor/jquery-migrate/jquery-migrate.min.js"></script>
		<script src="/core/vendor/jquery-ui/ui/jquery-ui.custom.js"></script>
		<script src="/core/vendor/underscore/underscore.js"></script>
		<script src="/core/vendor/moment/min/moment-with-locales.js"></script>
		<script src="/core/vendor/handlebars/handlebars.js"></script>
		<script src="/core/vendor/blueimp-md5/js/md5.js"></script>
		<script src="/core/vendor/bootstrap/js/tooltip.js"></script>
		<script src="/core/vendor/backbone/backbone.js"></script>
		<script src="/core/vendor/es6-promise/dist/es6-promise.js"></script>
		<script src="/core/vendor/davclient.js/lib/client.js"></script>
		<script src="/core/vendor/clipboard/dist/clipboard.js"></script>
		<script src="/core/vendor/bowser/src/bowser.js"></script>
		<script src="/core/js/jquery.ocdialog.js"></script>
		<script src="/core/js/oc-dialogs.js"></script>
		<script src="/core/js/js.js"></script>
		<script src="/core/js/l10n.js"></script>
		<script src="/core/js/octemplate.js"></script>
		<script src="/core/js/eventsource.js"></script>
		<script src="/core/js/config.js"></script>
		<script src="/core/search/js/search.js"></script>
		<script src="/core/js/oc-requesttoken.js"></script>
		<script src="/core/js/apps.js"></script>
		<script src="/core/js/mimetype.js"></script>
		<script src="/core/js/mimetypelist.js"></script>
		<script src="/core/vendor/snapjs/dist/latest/snap.js"></script>
		<script src="/core/js/oc-backbone.js"></script>
		<script src="/core/js/backgroundjobs.js"></script>
		<script src="/core/js/shareconfigmodel.js"></script>
		<script src="/core/js/sharemodel.js"></script>
		<script src="/core/js/sharescollection.js"></script>
		<script src="/core/js/shareitemmodel.js"></script>
		<script src="/core/js/sharedialogresharerinfoview.js"></script>
		<script src="/core/js/sharedialoglinklistview.js"></script>
		<script src="/core/js/sharedialoglinkshareview.js"></script>
		<script src="/core/js/sharedialogmailview.js"></script>
		<script src="/core/js/sharedialoglinksocialview.js"></script>
		<script src="/core/js/sharedialogexpirationview.js"></script>
		<script src="/core/js/sharedialogshareelistview.js"></script>
		<script src="/core/js/sharedialogview.js"></script>
		<script src="/core/js/share.js"></script>
		<script src="/core/js/files/fileinfo.js"></script>
		<script src="/core/js/files/client.js"></script>
		<script src="/apps/federatedfilesharing/js/public.js"></script>
		<script src="/apps/files/js/file-upload.js"></script>
		<script src="/apps/files_sharing/js/public.js"></script>
		<script src="/apps/files/js/fileactions.js"></script>
		<script src="/apps/files/js/fileactionsmenu.js"></script>
		<script src="/apps/files/js/jquery.fileupload.js"></script>
		<script src="/apps/files/js/filesummary.js"></script>
		<script src="/apps/files/js/breadcrumb.js"></script>
		<script src="/apps/files/js/fileinfomodel.js"></script>
		<script src="/apps/files/js/newfilemenu.js"></script>
		<script src="/apps/files/js/files.js"></script>
		<script src="/apps/files/js/filelist.js"></script>
		<script src="/apps/files/js/keyboardshortcuts.js"></script>
		<script>
		(function ($, OC) {

			$(document).ready(function () {
				var data = $("data[key='cernboxauthtoken']");
				var accessToken = data.attr('x-access-token');
				if(accessToken) {
					OC["X-Access-Token"] = accessToken;
					/*
					OC.Files.getClient()["_defaultHeaders"]["X-Access-Token"] = accessToken;

					$.ajaxSetup({
						    headers: { 'X-Access-Token': accessToken }
					});

					$(document).on('ajaxSend',function(elm, xhr, settings) {
						xhr.setRequestHeader('X-Access-Token', accessToken);
					});
					*/

					XMLHttpRequest.prototype.origOpen = XMLHttpRequest.prototype.open;
					XMLHttpRequest.prototype.open   = function () {
						this.origOpen.apply(this, arguments);
						this.setRequestHeader('X-Access-Token', accessToken);
					};

				}
			});

		})(jQuery, OC);
		</script>
	<body id="body-public">
	<data key="cernboxauthtoken" x-access-token="test" />
	<noscript>
	<div id="nojavascript">
	<div> This application requires JavaScript for correct operation. Please <a href="http://enable-javascript.com/" target="_blank" rel="noreferrer">enable JavaScript</a> and reload the page.</div>
	</div>
	</noscript>

	<div id="notification-container">
		<div id="notification" style="display: none;"></div>
	</div>

	<input type="hidden" id="filesApp" name="filesApp" value="1">
	<input type="hidden" id="isPublic" name="isPublic" value="1">
	<input type="hidden" name="dir" value="/" id="dir">
	<input type="hidden" name="downloadURL" value="https://localhost:4443/index.php/s/jIKrtrkXCIXwg1y/download" id="downloadURL">
	<input type="hidden" name="sharingToken" value="jIKrtrkXCIXwg1y" id="sharingToken">
	<input type="hidden" name="filename" value="Test folder" id="filename">
	<input type="hidden" name="mimetype" value="httpd/unix-directory" id="mimetype">
	<input type="hidden" name="previewSupported" value="false" id="previewSupported">
	<input type="hidden" name="mimetypeIcon" value="/core/img/filetypes/folder.svg" id="mimetypeIcon">
	<input type="hidden" name="filesize" value="28" id="filesize">
	<input type="hidden" name="maxSizeAnimateGif" value="10" id="maxSizeAnimateGif">

	<header>
		<div id="header" class="share-folder" data-protected="false"
			 data-owner-display-name="admin" data-owner="admin" data-name="Test folder">
			<a href="/index.php" title="" id="owncloud">
				<h1 class="logo-icon">
					ownCloud			</h1>
			</a>

			<div id="logo-claim" style="display:none;"></div>
					<div class="header-right">
				<span id="details">
					<a href="https://localhost:4443/index.php/s/jIKrtrkXCIXwg1y/download" id="download" class="button">
						<img class="svg" alt="" src="/core/img/actions/download.svg"/>
						<span id="download-text">Download</span>
					</a>
				</span>
			</div>
				</div>
	</header>
	<div id="content-wrapper">
		<div id="content">
			<div id="preview">
								<div id="controls">
			<div class="actions creatable hidden">
				<div id="uploadprogresswrapper">
					<div id="uploadprogressbar">
						<em class="label outer" style="display:none"><span class="desktop">Uploading...</span><span class="mobile">...</span></em>
					</div>
					<input type="button" class="stop icon-close" style="display:none" value="" />
				</div>
			</div>
			<div id="file_action_panel"></div>
			<div class="notCreatable notPublic hidden">
				You donÃÂ¢ÃÂÃÂt have permission to upload or create files here		</div>
			<input type="hidden" name="permissions" value="" id="permissions">
		<input type="hidden" id="free_space" value="INF">
			<input type="hidden" id="publicUploadRequestToken" name="requesttoken" value="PTUadAJrOx8NOxZGNCEpEQtoAA0wQBMbCWcRT3ROFB8=:WcL6HZXeYsbiDDAfGGyhq9jJe7V7B7Xi3kzHJUmTs/g=" />
		<input type="hidden" id="dirToken" name="dirToken" value="jIKrtrkXCIXwg1y" />
			<input type="hidden" class="max_human_file_size"
			   value="(max INF PB)">
	</div>

	<div id="emptycontent" class="hidden">
		<div class="icon-folder"></div>
		<h2>No files in here</h2>
		<p class="uploadmessage hidden">Upload some content or sync with your devices!</p>
	</div>

	<div class="nofilterresults emptycontent hidden">
		<div class="icon-search"></div>
		<h2>No entries found in this folder</h2>
		<p></p>
	</div>

	<table id="filestable" data-allow-public-upload="no" data-preview-x="32" data-preview-y="32">
		<thead>
			<tr>
				<th id='headerName' class="hidden column-name">
					<div id="headerName-container">
						<input type="checkbox" id="select_all_files" class="select-all checkbox"/>
						<label for="select_all_files">
							<span class="hidden-visually">Select all</span>
						</label>
						<a class="name sort columntitle" data-sort="name"><span>Name</span><span class="sort-indicator"></span></a>
						<span id="selectedActionsList" class="selectedActions">
							<a href="" class="download">
								<span class="icon icon-download"></span>
								<span>Download</span>
							</a>
						</span>
					</div>
				</th>
				<th id="headerSize" class="hidden column-size">
					<a class="size sort columntitle" data-sort="size"><span>Size</span><span class="sort-indicator"></span></a>
				</th>
				<th id="headerDate" class="hidden column-mtime">
					<a id="modified" class="columntitle" data-sort="mtime"><span>Modified</span><span class="sort-indicator"></span></a>
						<span class="selectedActions"><a href="" class="delete-selected">
							<span>Delete</span>
							<span class="icon icon-delete"></span>
						</a></span>
				</th>
			</tr>
		</thead>
		<tbody id="fileList">
		</tbody>
		<tfoot>
		</tfoot>
	</table>
	<input type="hidden" name="dir" id="dir" value="" />
	<div class="hiddenuploadfield">
		<input type="file" id="file_upload_start" class="hiddenuploadfield" name="files[]" />
	</div>
	<div id="editor"></div><!-- FIXME Do not use this div in your app! It is deprecated and will be removed in the future! -->
	<div id="uploadsize-message" title="Upload too large">
		<p>
		The files you are trying to upload exceed the maximum size for file uploads on this server.	</p>
	</div>
						</div>
		</div>
		<footer>
			<p class="info">
				<a href="https://owncloud.org" target="_blank" rel="noreferrer">ownCloud</a> ÃÂ¢ÃÂÃÂ A safe home for all your data		</p>
		</footer>
	</div>
	</body>
</html>
`

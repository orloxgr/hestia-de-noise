<?php
$install = $argv[1];
$escape = static fn($v) => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$actor = 'admin';
$fields = static function ($action) use ($escape) {
    echo '<input type="hidden" name="action" value="' . $escape($action) . '"><input type="hidden" name="token" value="fixture-token">';
};
$policy = ['custom_endpoints'=>[['id'=>'saved_rule','name'=>'Saved rule','enabled'=>true,'type'=>'regex',
    'pattern'=>'^/saved\.sql$','targets'=>[],'also_ban'=>true,'duration_seconds'=>7200]]];
$policy['endpoint_404']=['enabled'=>false,'paths'=>['/kept.php'],'targets'=>['alice/one.test'],'duration_seconds'=>7200];
$data = ['sites'=>[['key'=>'alice/one.test','domain'=>'one.test','owner'=>'alice']],
    'analysis'=>['inventory_kind'=>'endpoints','minutes'=>1440,'totals'=>['requests'=>2],'findings_total'=>1,
        'bytes_read'=>1024,'partial'=>false,'note'=>'Fixture only','page'=>1,'pages'=>1,'per_page'=>20,
        'findings'=>[['domain'=>'one.test','site'=>'alice/one.test','path'=>'/backup.zip','candidate'=>'/backup.zip',
            'count'=>2,'successful'=>0,'missing'=>2,'category'=>'Backup / database filename','advice'=>'Review first',
            'statuses'=>['404'=>2],'methods'=>['GET'=>2],'clients'=>1,'first'=>1000,'last'=>1001,
            'agents'=>['Scanner <script>bad()</script>'=>2]]]]];
$data['analysis']['suggestions']=[['site'=>'alice/one.test','domain'=>'one.test','category'=>'Backup archives','action'=>'block',
    'title'=>'Proposed filename rule','detail'=>'Exactly the observed filenames','paths'=>['/backup.zip','/backup.rar'],
    'missing_paths'=>['/backup.zip','/backup.rar'],'count'=>3,'statuses'=>['404'=>3],
    'pattern'=>'^(?:/backup\.rar|/backup\.zip)$','type'=>'regex']];
?>
<!doctype html><html><head><meta charset="utf-8"><style><?php readfile($install.'/panel/ui.css'); ?></style></head><body>
<div id="hdn-container"><form id="hdn-settings" method="post"><?php $fields('save'); ?></form>
<?php require $install.'/panel/endpoints.php'; ?></div>
<script id="hdn-agent-presets" type="application/json">{}</script>
<script id="hdn-probe-presets" type="application/json">{}</script>
<script id="hdn-rule-presets" type="application/json">{}</script>
<script><?php readfile($install.'/panel/rules.js'); ?></script>
<script><?php readfile($install.'/panel/lists.js'); ?></script>
</body></html>

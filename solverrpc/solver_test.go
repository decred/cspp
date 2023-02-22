package solverrpc

import (
	"fmt"
	"math/big"
	"sort"
	"testing"
)

var F256r1 = decodeBig("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)

func decodeBig(s string, base int) *big.Int {
	b, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic(s)
	}
	return b
}

func sortBig(b []*big.Int) {
	sort.Slice(b, func(i, j int) bool {
		return b[i].Cmp(b[j]) < 0
	})
}

type test struct {
	n        int
	messages []*big.Int
	coeffs   []*big.Int
	field    *big.Int
}

var tests = []test{{
	n: 3,
	messages: []*big.Int{
		decodeBig("52630499d10d42b4f1302b42a03aa7b7e1c70f9e325eb24c8708b8f49eaef6cd", 16),
		decodeBig("9034a3a895c93d68e32f360ea578403f27b683bf4c6b355b3fc07de40da1bbca", 16),
		decodeBig("ad6764b2b135d2ed0e9d2080c91c0738c55391c76f80b024fbce8cabb9eb7967", 16),
	},
	coeffs: []*big.Int{
		decodeBig("10209112750741618021595020692373315114462165733802158385966313962636466992775", 10),
		decodeBig("57233369253256883785716066111021586963703924274473955348356783175795397420836", 10),
		decodeBig("65131372804561188098886548940761405986392102876379930878143412912843006946303", 10),
		decodeBig("115792089210356248762697446949407573530086143415290314195533631308867097853950", 10),
	},
	field: F256r1,
}, {
	n: 10,
	messages: []*big.Int{
		decodeBig("fa9bf3fe0a431b52ede3c051944e4feb1aabc0829025c8b6b5e82ff4d1f30097", 16),
		decodeBig("7b22f15c80f07671a6fa8f7b583eff9963166c25073cd0560ebb78cdb11ee8a1", 16),
		decodeBig("3bc1dbffba5e7d14abeb946e62e29df7e449abcc11c455c893276593e0e64a7e", 16),
		decodeBig("a126dd6299ff7915f8312edbc5d6be03486ae33f6d5d6e53b04420bdb0aaaab9", 16),
		decodeBig("e0f0c36426d495953a12db6a05f5a0b4a625b46ecfdb59e4ae502710020d7bc0", 16),
		decodeBig("9541dea609d864df279ef55f7535ad1890a3805e2da36f119cbcd3d1014c0a97", 16),
		decodeBig("78920f9fcc984601b8d9ec31d3308acce8469836cff7a2e9c7377c060029d901", 16),
		decodeBig("43afbb90b13d79d0512333f32e297aad9aa21be04bcb2ecd2501fe292bbf533f", 16),
		decodeBig("8f726b711c3e01cfdbc80d2763e0f908d18c2bb024ee860ac01b1a007d27d3dc", 16),
		decodeBig("4abc867e3fc6933bb7bfd0f83fc441d7c81b87c4ac53b3bc78f52bf8e862cb7", 16),
	},
	coeffs: []*big.Int{
		decodeBig("72884472027362764597997241505979044453451881553842149469594099861661683061675", 10),
		decodeBig("34311056356805540110355813382092192244172544670002542038008645144400512593320", 10),
		decodeBig("37774296231998220937750671784616841279089545086876375111869889739378446996983", 10),
		decodeBig("54730845086869708188459177639234883566865859611357282586995609285861441109925", 10),
		decodeBig("19806710539988085241213085877292898276538534468413590282201654396576309778112", 10),
		decodeBig("85754436280157372159379525444153899980058219610706400120431190445993893756698", 10),
		decodeBig("108915743608270584242704851226664767545656833037127485019165969284053229096072", 10),
		decodeBig("52331706306555191955431452286826838261273314808958116305956652274428463462254", 10),
		decodeBig("80316936272027783598996613255834145676962582999403951031503563905134805027914", 10),
		decodeBig("11410738911814004993017127975997062614628330535195782066712345618565597204894", 10),
		decodeBig("115792089210356248762697446949407573530086143415290314195533631308867097853950", 10),
	},
	field: F256r1,
}, {
	n: 30,
	messages: []*big.Int{
		decodeBig("26b771540890d74e97e122d13e3fce4453f067eb9911e163e96fa63a25a99786", 16),
		decodeBig("2cd66046b25b71880e4cfaa8902b7e55b674f907561ca1402ddd7ff4c83a6b1", 16),
		decodeBig("1f2ed40de8aaaa6006c5121f4aa78e34d522e7a5e8796ce8379e60c215dcfda6", 16),
		decodeBig("f7623d9b78929a318e330619b9ee90a1ed73c02d3ec2d3d42945db541bbd71c", 16),
		decodeBig("6c07f1e9d18cd471386c20a4cd247c6f94ee5b4c2440f52791c2b71a932f0bd1", 16),
		decodeBig("30d5427a238a3e21145475798a7cbae5432d48321a1ac3b833b8117940ff3391", 16),
		decodeBig("1baaea2a28e7f80ecffa1118209055f43e670a29e65dbf042ebfb1d879689fd0", 16),
		decodeBig("83369f6725d78407245561f8b83711ea502f9b35dea349274eef8bf2aca57d15", 16),
		decodeBig("b4c16716b8a51ec13b651cec172e9a403d3b249a2983d3b7eb83fc35fa5dd20c", 16),
		decodeBig("d40e574e30a9d99da6a7db04dea3f9d1dfeb41b01f0290e1c48e447a440476e4", 16),
		decodeBig("e712367802d4ff2ee38b1a532b154b473c755bbe7e0294cb7dc317e46776808f", 16),
		decodeBig("698935cbec817f49e58cf7513e1ce4e8a0696b967c234c64162a9f7c3366c7f6", 16),
		decodeBig("931f7eac05ad4aa5e18b99a1b9c0319e5b0773c803380ea8e23bc1966966ff98", 16),
		decodeBig("91c6219a82a2a19e7da28ccbb53ab840d318182494a27323964d162f2389b642", 16),
		decodeBig("d147ace7e98bf90d1d8e507ca65cd5baa019b17f3ac9718612c77337e24abb71", 16),
		decodeBig("ef8e8157668071e6b47b5016615931b58f979281693eae74cec2b7a5b8a7fcaf", 16),
		decodeBig("4d983c7df17365951ef9b260f086fc5feece43ac49750a724a899dc0c8003449", 16),
		decodeBig("1e8c4fdfbf5958b63c6636e45b0f65ff1af6ba5b88e20e91d8d4f9d61678e221", 16),
		decodeBig("ef0429f4e528b1d15c15be3f0da09d898102ac1990e6ffa3da3864f242729845", 16),
		decodeBig("fc612e6f90d0cac7a07b500d43ec76c5b0e7fb487a2e783dea4fb0a3c76521bd", 16),
		decodeBig("82522aeb8cd902b50c61f90c5702474ff7fd40f685e5efac8f8c0c5bce6a0634", 16),
		decodeBig("c2a58679028a62ad9a0bf81592f050b31d5cbe85ecce699dc86f3b5dec877821", 16),
		decodeBig("f92df4100758d5e9e483aad9e04b20be4a7fc81e0f0d90a742ba0db3217f98ca", 16),
		decodeBig("6f46674b4bf23ae36100ef89ff35b0f04c47fce8e5fe64fd7a8f41a1386df7e7", 16),
		decodeBig("811db9cf5e2471b230ff9023fb5b8573cfcec3ff07a1fff8458053b59e367549", 16),
		decodeBig("3812fe544adb2c7a75c7878a58905a98d6a9070f2f42132edef8352720ad5767", 16),
		decodeBig("39bb237e791a7792512a61108272711d803048515f2615dc85ab136de753c144", 16),
		decodeBig("b0eefc928505ba86205e0a173d1b6c1578fcdcbb12e4e49f01b1186c57c64615", 16),
		decodeBig("d4e1ce781e53720dfff468dfdfbc9359e5ec131a05ed021d5f4f738cdd614267", 16),
		decodeBig("f1c3ebec472254ae2793e5280920837237e94fba87a4ab48bb8fe130a519fdb6", 16),
	},
	coeffs: []*big.Int{
		decodeBig("99181428741664025837149191709205705640549232117424321956461997348827802685852", 10),
		decodeBig("12652967227486775354745046416246075652327425839922952032660702308430659176528", 10),
		decodeBig("1581217132339523562519160992824435700950470957347501587126364488310530719494", 10),
		decodeBig("56016634934779457237185203800278649812613480955042524522421716887046813334167", 10),
		decodeBig("44906184680356139938743509952182627135814724231368093656855216968688901297233", 10),
		decodeBig("39439527543988498549559589048801496895240059367318779198596987192347884756861", 10),
		decodeBig("112688305673086598771167591471059888593178328862026302244746122177518420670051", 10),
		decodeBig("82527908871898948542608110820353553399704874136430712265302801264230827159065", 10),
		decodeBig("29676352152712853601978219148579401095985310411872887078971088340199725983008", 10),
		decodeBig("79272713125059218777106826596929876887701699025510763822571404587365089665259", 10),
		decodeBig("92707045027581570223883939664024509469767681844083109873483292102714363450405", 10),
		decodeBig("28245288532603713679046376854689465686920771339287158061588862042066714490038", 10),
		decodeBig("1359728077698880332770243228685614899115285819753865506372821832940292559331", 10),
		decodeBig("90248782127830638992740595735291921039900868848813422896411281183957886491508", 10),
		decodeBig("66069311157843732711567151949308496902647517246929198326556772808668809078697", 10),
		decodeBig("32931775655059303682149201308115050842171266123654659527189659373291484420139", 10),
		decodeBig("100039935629248419069685392690440008868594712550345428490200880957686155396278", 10),
		decodeBig("90302782111105756722478006984975987560418842561735140199676038556723414172809", 10),
		decodeBig("4080966546974710619128082448258053671336531119077868182111490113332859081031", 10),
		decodeBig("15437751335027439533138748433395634670160999910759008386974299512945018626465", 10),
		decodeBig("87072748666943490796185469514432763803756659755426019539244811875341198741346", 10),
		decodeBig("42308786601675760703953834332038021768094945969057500899837989036533652362318", 10),
		decodeBig("67777796084722080503991545415829800490672803788525083738047270372200635459041", 10),
		decodeBig("61316912140560027531595408622375913331950845127959680599755010822276818854842", 10),
		decodeBig("16609108234010272391533970936565854233796287043812439808637542725500764472051", 10),
		decodeBig("95273890903693173498701003841839713895780883751321131496426766951505481076922", 10),
		decodeBig("86305939802264577490428242857233606436269108139245415528004738156099975140714", 10),
		decodeBig("37946475163857073217314436575032748425301756660341373859844348181283887703107", 10),
		decodeBig("71372377522473716707197493690744375056679811245464290166703853547388875595079", 10),
		decodeBig("87985522980853589849222809368586545722755584553379711568707488382295261209174", 10),
		decodeBig("115792089210356248762697446949407573530086143415290314195533631308867097853950", 10),
	},
	field: F256r1,
}, {
	n: 50,
	messages: []*big.Int{
		decodeBig("54e86cdbd7a2b6b62feaaac0af00b1b3a43b760451e5ed8729499fcb9ab71755", 16),
		decodeBig("1b3e47016afd2b7cf845206e84f59d9c212dda90981aa56ff3282842f25ed2cb", 16),
		decodeBig("f8dc1f8e485e055a5842bcf19fd7b5506ba2136231536008f3fe271caff12378", 16),
		decodeBig("1421ee4cd4f6e8c0c77c2bd25ae61595256850973fc8b6892efe98e90b1fe7cc", 16),
		decodeBig("5e31cb81497202eab2f2bcda180ff3e664b56b9a811ca3bd66eefd2d8a2c9c2b", 16),
		decodeBig("8b57d02177677daa5575b21b66b3adce0c7f4e6e7212cdccadf7b330d93a6cb6", 16),
		decodeBig("c48daafc079463779e13d0f0c72e3354c737731aad134aa314c7a1046dc23fef", 16),
		decodeBig("7defad0dd22525b229aecd984d93ebad9d4dad658aba464c8f9066572460ffff", 16),
		decodeBig("13fd9c4ae37a01998f66ed7ce7eee5d4957c249a1c1525c38cda65e8ab8fd43c", 16),
		decodeBig("d7be9871576f9ddb8d0e1ac0999da618b3b8b2f8e502cc46b6e1bbab76ead65c", 16),
		decodeBig("f5ab0a53aae8ef23bc0dddb45548fb190b74867933f81386c0fec4875ee38d19", 16),
		decodeBig("d0aa0df20bffa13d1c7e689b1b435f308de6260bbf24b3664b35e9486f1b9414", 16),
		decodeBig("79d732665cf3b38c69f3a52193ad72013ce10d882b731b5b2ef985603e95fee7", 16),
		decodeBig("e20d548cec39abed3f05e6f9d5f76cdd92101b97330f2b4b973111d7d158951e", 16),
		decodeBig("7a3a89a72b8a293e62cbf74370753f84ba9dceba82029045c4362c451393df90", 16),
		decodeBig("848a1cb82eecc3610946aaf111f8f11bf6b299f355689c1057288faa7e2d0def", 16),
		decodeBig("ad9f7c1b52376ffdb1c0d85aeb791dc7990043120fa27ed1ac1dcc85a304d294", 16),
		decodeBig("38effa00b47acb4ef55edf7baecdd278c01e0ceb727d413a9828def9c5f5f467", 16),
		decodeBig("30447f041c1c8342aef65acd851379dd657d9516ebb0666c1981763119b1274b", 16),
		decodeBig("b44fb43e9a4e58a23c102af3f906587e80bf677a103c84b6d42bb731d17493ac", 16),
		decodeBig("7ce7270426c3001db09f3bb02d6f609bc76256ff69d930a263a22d966eb09761", 16),
		decodeBig("b23ec0ef4c2720e49ea172e38bd0d69be4a00f92aeca2e9a47bc7e926d6d1052", 16),
		decodeBig("4832fa1b8e0752587a2d054810aaba1e39ba6060c3b4c0c06de0bd755a1b22b3", 16),
		decodeBig("164ecc7c7341a4054a561f3a68c032233a5c6f8daec9912c561f09ee2e2d930c", 16),
		decodeBig("8d5dd5db1a7d5642e0ffc4247c2c29c3ddea534a1cca9311353fc69b7eebe91a", 16),
		decodeBig("af7b6358083910f6b7e55088e76167997620e7d213e62eeb1e04c7abe84242e8", 16),
		decodeBig("9d48ddf9b7265b73ad36c6f97065aea289e19576524c1e52e31755ace9413681", 16),
		decodeBig("7b41ab1485b5152167098629fd8e67b3e11047d485f63f0fcb97dbff91ef9755", 16),
		decodeBig("8075cc34dfd0b8e4ad4b6fd4f02fc0e0044fb02009fc8661cb59d2d16a8cc197", 16),
		decodeBig("8c1d3d27d28f661066776b5e2a640a390d96ef0a255e4246c68a456c92d89f60", 16),
		decodeBig("d90aa6b372d34543f5aa170c17269099cbca98c593943fde3e3fe7253453c266", 16),
		decodeBig("50dad0dfa39e819073719679e7ec475135e92843498ce29b4148f81a7b794171", 16),
		decodeBig("c65494613c19324801cbfc261fb2f0cf19b1c66611f486caabbfb90ec18de6d1", 16),
		decodeBig("2eef4c3d256ecdd31e4df4705263f5483fcd93d05152a175775b6c4a6abbb76e", 16),
		decodeBig("d491954ace05c1e457d7f1a583b5f777302381ee109b25f4f240dd4190aa5152", 16),
		decodeBig("25e2fc3d903cae076114be5835f52d5615422871a6802a75f79531d6f307ccf", 16),
		decodeBig("6fedc0c71eaef9ddac284f13c2dfa7dfec320894e71bdcc316cfcc25e5fe4bec", 16),
		decodeBig("f15f71354d3933f0723f3690c91ca69aecfe62832537d0728df1d8b1938f1df3", 16),
		decodeBig("c1c4e8c56e8984f6caad2816964d5314b45a5542e1d66eb5a6ab06e8fc33d627", 16),
		decodeBig("a7d7cd6f811a6c970263e94084652231a25cac50d5503a72ffd3d1fa1f1decc7", 16),
		decodeBig("8099365f794360239c698f82ba1b71b15322ec91cca8fee35b85a994b7d2ad58", 16),
		decodeBig("d7bed7088d30995fd2c0205b32247457844697d46e73482dbb80197bdeaf4e46", 16),
		decodeBig("fa8b3723dce3611048777a50f82488f2ca4d7b2bffa5ac9932ffc7dc406d68d4", 16),
		decodeBig("2d32e99e1eb60d9a57f9ea3ea8a4a67a8e5499c51d0e71bca48fcf5a3050ee24", 16),
		decodeBig("68b6ba651c7ca030f49aa9a0a9ddb51aeb0a97ad66ecb63e4c27dcc708b59f55", 16),
		decodeBig("82dd60b8b633b972fd33b915124b799e497ab03099a5d6e382612e8b9c9c2633", 16),
		decodeBig("596a66c72ff37fe9541acff00c48e9ca1da509281f4f2ffb52784a2c1c57c8bd", 16),
		decodeBig("9ba11acc0a14f5f7ab592c74a308c8aaae9d8d58d4af321e5df145213266546f", 16),
		decodeBig("2c0d9d17e0ba1644fcd5cfd8aa0b4d6b31e428c3ce134e48e9e4b6a2e63f459e", 16),
		decodeBig("839e8b48f6d714c739c7827e480570db0229e2f63ea7a8d3ee972ce6007b0416", 16),
	},
	coeffs: []*big.Int{
		decodeBig("79532921430405743870156042296486196721039366970196555100271577043772234463520", 10),
		decodeBig("50484113841795229679866286368929880534032606984964553147607717032156598206646", 10),
		decodeBig("66155160230360838374605491041673983963553681781649454923214968203505785060250", 10),
		decodeBig("27664402257107126846802051897666123740346135341418132014907686356193013545471", 10),
		decodeBig("79918868175688538840012415739362442592436043023244791997766265229386135599345", 10),
		decodeBig("41994129359701284343002948123311391425989759212464565897596250299471447489267", 10),
		decodeBig("64480327625633436272748553100776826687985639014892290890070426824872622668335", 10),
		decodeBig("25273398492296429324886571834598222862135374820697050203327507990749404643912", 10),
		decodeBig("31361205786408480782955388866270948478928726322776671339612476918583777340021", 10),
		decodeBig("95969643827618988602340489026395438675842621341187846392220965744816281560653", 10),
		decodeBig("33428274140291198087638088251395900874203242041067748806894068468967303333970", 10),
		decodeBig("112232960679271022478038959758854593088223799619218528426651196814276049850287", 10),
		decodeBig("21698464363959440765179202809645023430280769875278756839768696984100930471502", 10),
		decodeBig("65715889731632125628343836758725992093395139113976196243729883237948514692661", 10),
		decodeBig("70788160611314611694280290607966080125590389730790492257542053491131139336017", 10),
		decodeBig("87639215052987902306094675501380554782453311955826272782299554491021875751402", 10),
		decodeBig("113443924338098317072954481028318673129778609690644318915535538033233377826020", 10),
		decodeBig("74258548224178851338343159101465352703658515839872261203011937273036568003690", 10),
		decodeBig("2817551452558145338948975803039932027500246562600788778891336931727156898766", 10),
		decodeBig("48346761297018331204576952326812455715766614745127714576325502993117209518321", 10),
		decodeBig("4318326104551802530113355161940532745520393269652498106511555431642648487113", 10),
		decodeBig("115169212766798852240975300766042771111663624486312418921911099986931818416775", 10),
		decodeBig("50773368127659637573754691976847021603976896839072078741042130987101433853798", 10),
		decodeBig("79337975950924614335518280335335805866233417482600564409852374889332002867151", 10),
		decodeBig("111442264167690862957541893384005490165277299686095976860352843157485760594748", 10),
		decodeBig("30392565079621904515146680957642368823930586290361768530662123105235605282658", 10),
		decodeBig("65691899454929554668867686242948040401671262256837011871756329474529536594978", 10),
		decodeBig("54015684330180293175731806508545817049607225729468954839528839018305495978732", 10),
		decodeBig("38195270153504723195505849899958627443290948492953769045417187803110655158968", 10),
		decodeBig("18367295344509562289124642185396108019411544113407367233189578897163484995171", 10),
		decodeBig("77072183814059993385842257264745417777055573935198072074877636393587267724721", 10),
		decodeBig("115642326364686892071936589283773355560065507049713225133099638612463492608186", 10),
		decodeBig("115287643858618468169353132505948903965658959503996906885027485080365450884642", 10),
		decodeBig("15583355540879208712343536371342340675870790469427984268059932383633440976393", 10),
		decodeBig("39988761145557247896237948822796416412313021219971208894143771257153161434236", 10),
		decodeBig("26947958071611548496981686201454981826831045255022913100176492843015831535865", 10),
		decodeBig("55860191989910118576830442535329584679935055113494342463015701071606263282867", 10),
		decodeBig("115295347839953286039057176637964691355373564642879855302323560951175036574524", 10),
		decodeBig("63801751186744401711434010889563082300213974895809356764774891772484183532754", 10),
		decodeBig("57210318709299382408103864573199473217004331441896535101584671285818630616159", 10),
		decodeBig("105551973955624243231577158159779247436310045298415258423088916126348150847365", 10),
		decodeBig("26268680895725256927833735549536002196077761092077509938991582515351958906039", 10),
		decodeBig("27514232793523296732356352491912124502200335829225219571370635594035247684431", 10),
		decodeBig("96152264165744232104332581826675503305521527622590908265667653783012321132145", 10),
		decodeBig("91344060006311730659076097694769746330728450422198270339171186715847143320447", 10),
		decodeBig("32948334211233575163086909364325606674468024534922397591835763573095807363109", 10),
		decodeBig("44748882424561078299888619804828167087679630183862335900969494064108320360220", 10),
		decodeBig("115169401772778782951829833622320117455515390650989317070430256104779775396379", 10),
		decodeBig("35680311223497960211767851272869223661825949389232917918962234224681908573178", 10),
		decodeBig("29876141799191989758322420126864524670825056988825885088839710176460337635787", 10),
		decodeBig("115792089210356248762697446949407573530086143415290314195533631308867097853950", 10),
	},
	field: F256r1,
}, {
	n: 75,
	messages: []*big.Int{
		decodeBig("c8f5dc63f384c75196cd57c38ab74a24c88c28587a31eab7ed32b53e08144a44", 16),
		decodeBig("6f5953f4e85d2324d3a44968fccda666da4baec6a9d132ee399f92cad1bc5a0b", 16),
		decodeBig("7db25a1aa7dce63391fc5a159b01dd2196b3111d770d090e38c3008572f00282", 16),
		decodeBig("218667572a2e99537345a519cc0235f00eedf22c935923b2799ac76494813f5c", 16),
		decodeBig("d6c60752e4ecc338ed22b6a6407a8ddd62fad1b75f7708b3c4c630ac5f4bc6cb", 16),
		decodeBig("b880b97da99ca17e7f0a44ffdb08bf54d33a6db09ce5a8a1a392e10b148f6d89", 16),
		decodeBig("73f572e36cb544ba166e578861601dda6f4a725376847ed80c5f0b3c3114dc9d", 16),
		decodeBig("6155e83d0e12b905be11ad9da6ca5626384dd702e80d12971d046cd48b9b9e0e", 16),
		decodeBig("592e47ac989541909d728dc4ba65303c5ac8dadad05bb2dcad2ba2cc5dade49e", 16),
		decodeBig("925fcdf9eff09678214159b7cf8cdbcf778bf1ce026e2d329a8139e22a1ec2c8", 16),
		decodeBig("aa55fe951ef9fd972b8189ce5a1c89780f89f73b20621842fa9b3f4bf51c2725", 16),
		decodeBig("b38b97e57251cdb65adfc16e062d091d32bd481ecd3a604d138bedc9d6d4d3f5", 16),
		decodeBig("7bf17b3610c811be17043d3da5db6a682663001c720bd3deb707c7af94c75aaa", 16),
		decodeBig("2a28378b24e315bc58b5ada0354689eaea1404be2866b12e51c39c6d5745ae05", 16),
		decodeBig("fcd735bb4995185b62d836ee063080053e6010b5c30ba9a928ec1454b2fd02a7", 16),
		decodeBig("3b2f0762dbc88cca4b780124e779fc77ac32e15a63c3042485f0d6f5a3b026a2", 16),
		decodeBig("13ffd8ac1883e6367a855c66776a131795ac92b34843dfaea68533fb39e5a20e", 16),
		decodeBig("e329a683f6bd1b424a79de72fd3b37cf4de48050a5166bb0902b967dded6a0ab", 16),
		decodeBig("9378ed1bba560f4ba92c50a04e3e3fd24407771f0e24c09ba513ca69f6094168", 16),
		decodeBig("befb8a59f48af53b564df035d5aa3c12e1cbe7a0ffd37928ee7a248a5185eb3c", 16),
		decodeBig("827187f39db801da4c94837aee74cc8244ef1c8a78b9d750d4c68a50e9c5ec98", 16),
		decodeBig("8dfe5758423862d5c99de2596d56b038703f8c87151d12107b682d1a5e87cc82", 16),
		decodeBig("32df5455ae578fc1912c55710b538d826a1f4841201ff730fa2d2ac951da8182", 16),
		decodeBig("58734c07ba4220033b5350bdf336322905d9b541c69a979faa9971b59bb04b64", 16),
		decodeBig("ffe997c18483fa2e05719707c251bea33e1b7b4e55597582d0a62886f905b9f7", 16),
		decodeBig("aed1cd737320ef14bcf16b9570f7748c1b0795c7dfa2177fe734eb03ca6d1d7c", 16),
		decodeBig("6085d14b7b9269c0c798f1c204fc1cbe458bcdc9bf93de3c61f83c0eead7c78d", 16),
		decodeBig("cffc07a8e6f7f278b04bea54cf088d36b541c151f59bca579e1bc15555857a27", 16),
		decodeBig("3855d53d78821e0a89ef2f27d6ec67b02b2e8498754a498027ac269619e9e3b4", 16),
		decodeBig("d5505fa02e270819ba1241921d334d76653d86b2cc0f174c96af4854c7e37dc5", 16),
		decodeBig("548944e682da4e140a84b96e3c7fbb6e10dbb065904dc4e4425a181e0904754", 16),
		decodeBig("b95c1bd27e4ed8da278d2e6ef6482aeba1931941688a0cf231b186f96d67f045", 16),
		decodeBig("f5c39aa43d09daa3b9e31a67fb9e11cd46021e6973f4cd53840f7e186dc1b700", 16),
		decodeBig("870a20fcb8b8ad77dc67cecb67b3313f1b6106b11e5108b94b33b71d558f2521", 16),
		decodeBig("5116c343aff746a1ceb63315fc28d5c93698a4f789128571fab846265a173913", 16),
		decodeBig("c5a59d7e27c17d97381c99e62ac079fe2df1ee470db37e83cacdb710629c9c12", 16),
		decodeBig("311d18702f3d9dbc8f5a95c39f810495395f74c72bfb2937b095a4d6253cf14", 16),
		decodeBig("7a893fd68a52a4e7b1dc30d3f6956b4614d5e8da4f9d279160ac14de308839e2", 16),
		decodeBig("1acc91e5384f0dbd9a46f615c914209b8435b78221d29793e47bb869614828a9", 16),
		decodeBig("d45cbac069278c741c452a20ecb3a6c594118a9e0e39864382c4b0985e4e326b", 16),
		decodeBig("9ac1c55d36d6001fcb1fc4338761d89767506319fe15968c108f0f9dc6f947f", 16),
		decodeBig("90389af7ec66808975a9552299dfc080ac84022a5d80613e1074c6541d19f003", 16),
		decodeBig("9af429814032788d25b3d732b3a2c8ea97b2f70ebe5ab6e3867ea7f3af23aed0", 16),
		decodeBig("6d43fa8471d475e445bd785bd50e232b684736991709797a9c0ee7a82f59fcc7", 16),
		decodeBig("b29931ba2e44f659f6f0d43cee313abebbf1eafc54f8a919717cb7cd2b8f014a", 16),
		decodeBig("4d5bb94f1203ac2e4883aff2494e6ee80fe48d32d76a73f012904b61eaa55a4", 16),
		decodeBig("de0f9e51e8675f3d9482916ac7e3e2cf07a70efd410d1249558a9db011ef4e81", 16),
		decodeBig("b3afe244781fe177a85fd51267a9b937f9d7993bdd97c71e43b10f36ac3f20de", 16),
		decodeBig("34aaaff6e69a0199fd70001b2d0b6e2bad307f7a3a88bcf163f7d76fbde0cfe8", 16),
		decodeBig("368342fc3c189e9d24177adf09329cee018759c37d76712479f2bdb9b482fb82", 16),
		decodeBig("1d556823042f8ec5669c0594a63bd77843c7c28ff89564b28e0d853246f5b4e0", 16),
		decodeBig("cf37c68539e3765b142be2039556bcbbbd99657bd3c5091048beccb7a4f415c4", 16),
		decodeBig("3d732bc762c02701ddc6417d04847dcff440fe0e0d230c85c15fea7afd8989f", 16),
		decodeBig("1082f4767172f3b3b3c37b57717d9058bcef02a6b9d114f1e15b174c77e03f73", 16),
		decodeBig("1c30133146c025a3a217ebb54e3973a1427f489377876b959cba5dd919b0dd8d", 16),
		decodeBig("892730508520eb5bfe3624f892ea1c3903a9f70dedd467e0f92e825b98c9f8c5", 16),
		decodeBig("2d0e83211cd43bcc7531a58510da85d48bde715d26532af04dc0c01d12c43477", 16),
		decodeBig("e61d8e7195c39ad426d1760a4a90d0147321ea9b62b728166419a634c7d09909", 16),
		decodeBig("55333af5d9a073a2a8d31b5f5736d7eeb92c3f2c7858fa6c84bb695fe382cd25", 16),
		decodeBig("b8a7a5f1d86b1b0ea7c8105862ea634ec5d5201485a016c33e1a268a77c3df64", 16),
		decodeBig("39718b37a3a77a154d6674d742b60e84dfc7359085bff4835edd0489f267d8a9", 16),
		decodeBig("d10ec97cbb1f79570d499c76984ea31f7ed80010d4cfd1592ffeda195f69ae59", 16),
		decodeBig("e06c46c1ce806cb5e9faf459cc6638ad76aed50550ff16f1e2f41f22dc643ab3", 16),
		decodeBig("a6f6ffeac1681df32a756c142349b74d9c60f7d032ef744a52775829e9611d11", 16),
		decodeBig("d52c4cee0f7a4086feb98e25e56696ad60a014c39e07e5c0db9d8b36f35fa609", 16),
		decodeBig("e9986e4f2dafbbca159af5569f875a9502b0a69e6ed350da98b4af7b4217ed25", 16),
		decodeBig("3154255df00220fae1bb2af5bb43581a8d669d1786bf14e1c6218681441095c2", 16),
		decodeBig("82b542f2e753101e7bbbd3e06fe92b48a6a30cf593b27737b01cccb0d8bff633", 16),
		decodeBig("fe384aea1eac38a30e67e2e164191c40abd40be6dcc10289dbafbf01430c0d5e", 16),
		decodeBig("de658b273e9cb1d996e40530a906acc7c97d801f4a50de2595ad63f5ad224ed3", 16),
		decodeBig("17c4d79ab4f04169b7239ed4b7f69da299bd46302686029f0975465ddaf8c1dd", 16),
		decodeBig("224d6afe4bf89cdcf16ab365032ed4ed9fccea6814acd63bdf39b8a8af66b9ec", 16),
		decodeBig("d8b557e74b5495f109439597cce2d8475085111cb5a42d2ddf824c46fbbc95c1", 16),
		decodeBig("f3214b8cdfa236a3369f102cbf4c9cc9a4b201fdab918af3df0096485ae1f178", 16),
		decodeBig("b684a4f772d622b5fd895201cbf1bec0a7914067134131624396c32dab14190a", 16),
	},
	coeffs: []*big.Int{
		decodeBig("91518449195416416025746857724785811692165712789180872671253739906875801663252", 10),
		decodeBig("81174593772310329634881627464489494041355667039414439262732844321505600999436", 10),
		decodeBig("106335242732883027811520669645603201007920845991502754338671190122089553629288", 10),
		decodeBig("64625242127703466741216507106336741369934236606963402378882662623981260425754", 10),
		decodeBig("20103231867293764702680073899841790557040606842903922677783653821968274675338", 10),
		decodeBig("48097814908777824790033464114834315143555574903761717959384621802970587515410", 10),
		decodeBig("2031366036003479693188300573341324458807538323637524454801294882453781774625", 10),
		decodeBig("10897575132083151712273629591863530681340826291848264933400702038820962081608", 10),
		decodeBig("49381907018530333840417898775186192530270215665022932035618073969433309887420", 10),
		decodeBig("96593377084651582928642338738185545128536092835441655769081215844751519764442", 10),
		decodeBig("80915533415378987636187615981345905935977686017110739320733969484455715645322", 10),
		decodeBig("48092230759449588646570369306050330156125367806720443462238380174521296385918", 10),
		decodeBig("76628090147848369373488963980753254739288860494420969880418076660366259942912", 10),
		decodeBig("6951702230987979747626201219921790421231594930660559768169771241431910637334", 10),
		decodeBig("16839174788741426582997192530110705916605159767076388819195816154424135727015", 10),
		decodeBig("77992443901325588206149183479683899689438507885513108284303021339179911166488", 10),
		decodeBig("75663984661883071042404222448910106407082635611916422208092421339505419003940", 10),
		decodeBig("114489203882421245239678761538400028884205135011412096569071202719989320331128", 10),
		decodeBig("24557454934071210869678920356029628627202217539929361613816838821528998295533", 10),
		decodeBig("26519687402689729946802293019961606647705049046649688053441007064112827828371", 10),
		decodeBig("31461982377546221910185156623193047044593905476185054961231811109330017100889", 10),
		decodeBig("89822487929126866538617565415383413072889667424659466672172922018817764037202", 10),
		decodeBig("100289132255641213300831614328287106224791838307304418068245048578924487065967", 10),
		decodeBig("29642153538003009630459627204394164734658713581195082440340220732573744224315", 10),
		decodeBig("57801598467471115953088246416999298420117463524749640510546537483666411316578", 10),
		decodeBig("75498414602126420379955244490038364307791434178430546229343007537711687311268", 10),
		decodeBig("31503524149078419566544858977294425252813614284996143974580564766858909858510", 10),
		decodeBig("8465508153904037195729912102418030781627293056539628776160530200215074110565", 10),
		decodeBig("56571891367875435200691649285286428087257549917140323392231354695391067025697", 10),
		decodeBig("8015678673365074002137363217014297199014379165344212718720682207371118871674", 10),
		decodeBig("59011589331149041283147355463447055195375983446802007535861570159251815881695", 10),
		decodeBig("83230251769357034782905119877020707466321227429235532880640970034977712675202", 10),
		decodeBig("60626785293954010289811050027443809493646903058614511685107004753285916404468", 10),
		decodeBig("98556831077722822267025638841901027150125525538474149069510535460044572319719", 10),
		decodeBig("52674613476494553284657948258624378437172399614871929993475954714875258589187", 10),
		decodeBig("5982191414228476251612459647114138279808580171108126313398154761135605790734", 10),
		decodeBig("53220582836726355958720556824799391584515127621797409383435986511979998190071", 10),
		decodeBig("5343272010425741352264216763304620226077197584295401897559025479808357625227", 10),
		decodeBig("56421155503547687396913777266498296987461287291192744456948103786087021992193", 10),
		decodeBig("76913417947362297958362111940692194671373296427966450702010811874639757793884", 10),
		decodeBig("90176036664191546527268362480313709848089884376712208767706705355709757843225", 10),
		decodeBig("39253332407492312417197817085761830415634970085257121448659795017588440603528", 10),
		decodeBig("89105962287060537298378937009256650692245441390921033837400018020769272556049", 10),
		decodeBig("1867660860330960258233009040055192556724331047070523422853458742428468731789", 10),
		decodeBig("42600332695256548972823551816395083265403459716318234770767774063653592352966", 10),
		decodeBig("53796131823063765933349274195421244039725349114556926721505406958659836223557", 10),
		decodeBig("45966155097576114672637514988415886948229994609631326556209558890705456658641", 10),
		decodeBig("53826443706364608912774755228911187500287162602018419470174686449272848316879", 10),
		decodeBig("35998826839690221279708645220902092077302727810751665459666562755738167159895", 10),
		decodeBig("35312346740023056742725629815368698330155083901002299782282746551002610999422", 10),
		decodeBig("4137673943695533644399697194298555633832519025832511519321927844294005797183", 10),
		decodeBig("13674009275441825983221987612120250424249577018921970267517137416383737992169", 10),
		decodeBig("59487465437473559053420738785595771544277485933187089385112781280349377810043", 10),
		decodeBig("84483120235592247457620281876672581427380372112031089448262310017335527306806", 10),
		decodeBig("54048635426246206079088340335078245058213790667328338505120805850396487306610", 10),
		decodeBig("10633148690340448234991619010823955607954528018088517335545052530117777941618", 10),
		decodeBig("81236979846878172351237867492903691167510759846645153922040524131628849213437", 10),
		decodeBig("67245431672236504194682671296700742637517915160859879920146144539773718340978", 10),
		decodeBig("92367646995151243518442484972814483322774905202949045730473925258922376665188", 10),
		decodeBig("37743947563149065326374468496884174466881384615454317758920138403944482345604", 10),
		decodeBig("41430545684242316558533080739465778726581773411565887747036081469131979025306", 10),
		decodeBig("18496229621436323240677120018185776320311079812388147914389582377094655452895", 10),
		decodeBig("11593779997383861404336019880679184552068697509650931554373210623600539928612", 10),
		decodeBig("108733511641308249151134635214780954988326736661883929942710380076962300125364", 10),
		decodeBig("62880627323790398530278853660790759371245769994899939834101543170670932522024", 10),
		decodeBig("53322498070438800576633634298635146699475163548857515719138554112449738279779", 10),
		decodeBig("112576011669649954769570236531325257820224249159246244735984430696617577779684", 10),
		decodeBig("64544864243451977422444635510377815032330438794659450489912018608927893266863", 10),
		decodeBig("48654694257032892459725808486648371664072903385256143211205460115402265911836", 10),
		decodeBig("85004472521448770436601626417055893108389655557691514998852351621090870684513", 10),
		decodeBig("101385982041742746291627417679525852604663171020064594853370091426741672526397", 10),
		decodeBig("88879944108534945435198521943853463727755143817064071737168146165013447608891", 10),
		decodeBig("14541498426344970148615256775797986980699229497143877797475158922636857870551", 10),
		decodeBig("47262873274219508579170740999067873238800447785070922255964626561670212289146", 10),
		decodeBig("79770755447290969396363118436123510766263354276232187679407901249340390330807", 10),
		decodeBig("115792089210356248762697446949407573530086143415290314195533631308867097853950", 10),
	},
	field: F256r1,
}}

func TestRoots(t *testing.T) {
	for i := range tests {
		roots, err := Roots(tests[i].coeffs, tests[i].field)
		if err != nil {
			t.Error(err)
			continue
		}
		if len(roots) != len(tests[i].messages) {
			t.Error("wrong root count")
			continue
		}
		sortBig(tests[i].messages)
		sortBig(roots)
		for j := range roots {
			if roots[j].Cmp(tests[i].messages[j]) != 0 {
				t.Error("recovered wrong message")
			}
		}
	}
}

func BenchmarkRoots(b *testing.B) {
	for i := range tests {
		b.Run(fmt.Sprintf("%d", tests[i].n), func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				Roots(tests[i].coeffs, tests[i].field)
			}
		})
	}
}

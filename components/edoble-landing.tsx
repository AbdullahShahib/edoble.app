import { Feather } from '@expo/vector-icons';
import { StatusBar } from 'expo-status-bar';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Linking, Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, View, useWindowDimensions, type LayoutChangeEvent } from 'react-native';

type SectionKey = 'services' | 'work' | 'why' | 'about' | 'contact';

type ServiceCardData = {
  number: string;
  icon: keyof typeof Feather.glyphMap;
  title: string;
  description: string;
};

type ProjectCardData = {
  title: string;
  category: string;
  accent: string;
  aspect: 'large' | 'small';
};

type SelectOption = {
  label: string;
  value: string;
};

const brand = {
  background: '#F7F6F2',
  surface: '#FFFFFF',
  text: '#141414',
  muted: '#6B6B6B',
  accent: '#C9A96E',
  accentDark: '#A07840',
  border: '#E8E6E0',
  overlay: 'rgba(20,20,20,0.85)',
};

const navItems = [
  { label: 'Services', key: 'services' as SectionKey },
  { label: 'Work', key: 'work' as SectionKey },
  { label: 'About', key: 'about' as SectionKey },
  { label: 'Contact', key: 'contact' as SectionKey },
];

const serviceCards: ServiceCardData[] = [
  {
    number: '01',
    icon: 'monitor',
    title: 'Website Development',
    description: 'Custom websites built for performance, conversion, and identity.',
  },
  {
    number: '02',
    icon: 'smartphone',
    title: 'App Development',
    description: 'Mobile and web apps engineered for real users and real scale.',
  },
  {
    number: '03',
    icon: 'layout',
    title: 'UI/UX Design',
    description: 'Interfaces that feel inevitable - intuitive, considered, refined.',
  },
  {
    number: '04',
    icon: 'bar-chart-2',
    title: 'Branding & Marketing',
    description: 'Visual identity and digital strategy that makes you memorable.',
  },
];

const projectCards: ProjectCardData[] = [
  { title: 'Northstar Commerce', category: 'E-commerce', accent: '#C9A96E', aspect: 'large' },
  { title: 'Signal Studio', category: 'Brand system', accent: '#141414', aspect: 'small' },
  { title: 'Ledger Room', category: 'Product design', accent: '#A07840', aspect: 'small' },
  { title: 'Harbor Health', category: 'Web platform', accent: '#6B6B6B', aspect: 'large' },
];

const advantages = [
  {
    title: 'Deadline-Driven',
    description: "We've never missed a launch date. Timelines are commitments.",
  },
  {
    title: 'Design-First Thinking',
    description: 'Every decision - layout, font, color - is intentional, not accidental.',
  },
  {
    title: 'Full-Stack Delivery',
    description: 'Design to deployment under one roof. No handoff chaos.',
  },
];

const footerColumns = {
  services: ['Website Development', 'App Development', 'UI/UX Design', 'Branding & Marketing'],
  company: ['About', 'Work', 'Contact'],
};

const budgetOptions: SelectOption[] = [
  { label: 'Under ₹50K', value: 'Under ₹50K' },
  { label: '₹50K–₹1.5L', value: '₹50K–₹1.5L' },
  { label: '₹1.5L–₹5L', value: '₹1.5L–₹5L' },
  { label: '₹5L+', value: '₹5L+' },
];

const serviceOptions: SelectOption[] = [
  { label: 'Website', value: 'Website' },
  { label: 'App', value: 'App' },
  { label: 'UI/UX Design', value: 'UI/UX Design' },
  { label: 'Branding', value: 'Branding' },
  { label: 'Other', value: 'Other' },
];

function LogoMark({ size = 36, subtle = false }: { size?: number; subtle?: boolean }) {
  return (
    <View
      style={[
        styles.logoMark,
        {
          width: size,
          height: size,
          borderRadius: size / 2,
          opacity: subtle ? 0.06 : 1,
        },
      ]}>
      <Text style={[styles.logoLetter, { fontSize: size * 0.46 }]}>E</Text>
    </View>
  );
}

function SectionHeading({
  eyebrow,
  title,
  body,
  dark = false,
  align = 'left',
  eyebrowRef,
  titleRef,
  bodyRef,
}: {
  eyebrow: string;
  title: string;
  body?: string;
  dark?: boolean;
  align?: 'left' | 'center';
  eyebrowRef?: (node: Text | null) => void;
  titleRef?: (node: Text | null) => void;
  bodyRef?: (node: Text | null) => void;
}) {
  return (
    <View style={[styles.headingBlock, align === 'center' ? styles.centerAlign : null]}>
      <View style={[styles.eyebrowRow, align === 'center' ? styles.centerJustify : null]}>
        <View style={[styles.eyebrowRule, dark ? styles.eyebrowRuleDark : null]} />
        <Text ref={eyebrowRef} style={[styles.eyebrow, dark ? styles.eyebrowDark : null]}>
          {eyebrow}
        </Text>
      </View>
      <Text ref={titleRef} style={[styles.sectionTitle, dark ? styles.sectionTitleDark : null, align === 'center' ? styles.centerText : null]}>
        {title}
      </Text>
      {body ? (
        <Text ref={bodyRef} style={[styles.sectionBody, dark ? styles.sectionBodyDark : null, align === 'center' ? styles.centerText : null]}>
          {body}
        </Text>
      ) : null}
    </View>
  );
}

function SelectField({
  label,
  value,
  placeholder,
  options,
  onChange,
}: {
  label: string;
  value: string;
  placeholder: string;
  options: SelectOption[];
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);

  return (
    <View style={styles.fieldGroup}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <Pressable onPress={() => setOpen((current) => !current)} style={styles.selectTrigger}>
        <Text style={[styles.inputText, !value ? styles.placeholderText : null]}>{value || placeholder}</Text>
        <Feather name={open ? 'chevron-up' : 'chevron-down'} size={18} color={brand.muted} />
      </Pressable>
      {open ? (
        <View style={styles.selectMenu}>
          {options.map((option) => (
            <Pressable
              key={option.value}
              onPress={() => {
                onChange(option.value);
                setOpen(false);
              }}
              style={styles.selectOption}>
              <Text style={styles.selectOptionText}>{option.label}</Text>
            </Pressable>
          ))}
        </View>
      ) : null}
    </View>
  );
}

function FormField({
  label,
  value,
  onChangeText,
  placeholder,
  keyboardType,
  multiline = false,
}: {
  label: string;
  value: string;
  onChangeText: (text: string) => void;
  placeholder: string;
  keyboardType?: 'default' | 'email-address';
  multiline?: boolean;
}) {
  return (
    <View style={styles.fieldGroup}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <TextInput
        value={value}
        onChangeText={onChangeText}
        placeholder={placeholder}
        placeholderTextColor="#9B988F"
        keyboardType={keyboardType}
        multiline={multiline}
        style={[styles.textInput, multiline ? styles.textArea : null]}
      />
    </View>
  );
}

function ServiceCard({
  item,
  index,
  register,
}: {
  item: ServiceCardData;
  index: number;
  register: (index: number) => (node: View | null) => void;
}) {
  const [hovered, setHovered] = useState(false);

  return (
    <Pressable
      ref={register(index)}
      onHoverIn={() => setHovered(true)}
      onHoverOut={() => setHovered(false)}
      style={({ pressed }) => [styles.serviceCard, hovered || pressed ? styles.serviceCardHover : null]}>
      <Text style={styles.serviceNumber}>{item.number}</Text>
      <View style={styles.serviceIconWrap}>
        <Feather name={item.icon} size={32} color={brand.accent} />
      </View>
      <Text style={styles.serviceTitle}>{item.title}</Text>
      <Text style={styles.serviceDescription}>{item.description}</Text>
      <Text style={[styles.cardLink, hovered ? styles.cardLinkVisible : null]}>Learn More →</Text>
    </Pressable>
  );
}

function ProjectCard({ item, index, register }: { item: ProjectCardData; index: number; register: (index: number) => (node: View | null) => void }) {
  const [hovered, setHovered] = useState(false);

  return (
    <Pressable
      ref={register(index)}
      onHoverIn={() => setHovered(true)}
      onHoverOut={() => setHovered(false)}
      style={[styles.projectCard, item.aspect === 'large' ? styles.projectLarge : styles.projectSmall]}>
      <View style={[styles.projectVisual, { backgroundColor: item.accent }]}>
        <View style={styles.projectOrb} />
        <View style={[styles.projectRibbon, item.aspect === 'large' ? styles.projectRibbonLarge : styles.projectRibbonSmall]}>
          <Text style={styles.projectRibbonText}>Coming Soon</Text>
        </View>
      </View>
      <View style={styles.projectBar}>
        <View style={styles.projectBarText}>
          <Text style={styles.projectName}>{item.title}</Text>
          <Text style={styles.projectCategory}>{item.category}</Text>
        </View>
        <Text style={styles.projectArrow}>→</Text>
      </View>
      <View style={[styles.projectOverlay, hovered ? styles.projectOverlayVisible : null]}>
        <Text style={styles.projectOverlayTitle}>{item.title}</Text>
        <View style={styles.tagRow}>
          {[item.category, 'Strategy', 'Launch'].map((tag) => (
            <View key={tag} style={styles.tagPill}>
              <Text style={styles.tagText}>{tag}</Text>
            </View>
          ))}
        </View>
        <Text style={styles.projectOverlayLink}>View Project →</Text>
      </View>
    </Pressable>
  );
}

function StatBlock({ value, label }: { value: string; label: string }) {
  return (
    <View style={styles.statBlock}>
      <Text style={styles.statValue}>{value}</Text>
      <Text style={styles.statLabel}>{label}</Text>
    </View>
  );
}

function SocialLink({ icon, href, label }: { icon: keyof typeof Feather.glyphMap; href: string; label: string }) {
  return (
    <Pressable onPress={() => Linking.openURL(href)} style={styles.socialLink} accessibilityLabel={label}>
      <Feather name={icon} size={18} color="rgba(255,255,255,0.85)" />
    </Pressable>
  );
}

export function EdobleLanding() {
  const { width, height } = useWindowDimensions();
  const isDesktop = width >= 960;
  const scrollRef = useRef<ScrollView>(null);
  const sectionOffsets = useRef<Record<SectionKey, number>>({ services: 0, work: 0, why: 0, about: 0, contact: 0 });
  const serviceCardRefs = useRef<Array<View | null>>([]);
  const projectCardRefs = useRef<Array<View | null>>([]);
  const heroEyebrowRef = useRef<any>(null);
  const heroLineOneRef = useRef<any>(null);
  const heroLineTwoRef = useRef<any>(null);
  const heroCopyRef = useRef<any>(null);
  const heroActionsRef = useRef<any>(null);
  const heroVisualRef = useRef<any>(null);
  const servicesHeadingRef = useRef<any>(null);
  const workHeadingRef = useRef<any>(null);
  const workTitlesRef = useRef<any>(null);
  const workImagesRef = useRef<any>(null);
  const whyHeadingRef = useRef<any>(null);
  const aboutHeadingRef = useRef<any>(null);
  const contactHeadingRef = useRef<any>(null);
  const servicesSectionRef = useRef<any>(null);
  const workSectionRef = useRef<any>(null);
  const whySectionRef = useRef<any>(null);
  const aboutSectionRef = useRef<any>(null);
  const contactSectionRef = useRef<any>(null);
  const [scrolled, setScrolled] = useState(false);
  const [scrollY, setScrollY] = useState(0);
  const [menuOpen, setMenuOpen] = useState(false);
  const [stats, setStats] = useState({ projects: '0+', services: '0', retention: '0%' });
  const [statsAnimated, setStatsAnimated] = useState(false);
  const [form, setForm] = useState({
    name: '',
    email: '',
    service: '',
    budget: '',
    message: '',
  });

  const mobileMenuItems = useMemo(() => [...navItems, { label: 'Start a Project', key: 'contact' as SectionKey }], []);

  const registerServiceCard = (index: number) => (node: View | null) => {
    serviceCardRefs.current[index] = node;
  };

  const registerProjectCard = (index: number) => (node: View | null) => {
    projectCardRefs.current[index] = node;
  };

  const handleSectionLayout = (key: SectionKey) => (event: LayoutChangeEvent) => {
    sectionOffsets.current[key] = event.nativeEvent.layout.y;
  };

  const scrollToSection = (key: SectionKey) => {
    const target = Math.max(sectionOffsets.current[key] - 72, 0);
    scrollRef.current?.scrollTo({ y: target, animated: true });
    setMenuOpen(false);
  };

  const updateField = (key: keyof typeof form) => (value: string) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  useEffect(() => {
    let mounted = true;
    let cleanup = () => undefined;

    if (typeof window === 'undefined') {
      return undefined;
    }

    void (async () => {
      const gsapModule = await import('gsap');
      const scrollTriggerModule = await import('gsap/ScrollTrigger');
      if (!mounted) {
        return;
      }

      const gsap = gsapModule.default;
      const { ScrollTrigger } = scrollTriggerModule;
      gsap.registerPlugin(ScrollTrigger);

      const heroTargets = [heroEyebrowRef.current, heroLineOneRef.current, heroLineTwoRef.current, heroCopyRef.current, heroActionsRef.current].filter(Boolean);

      gsap.from(heroTargets, {
        y: 40,
        opacity: 0,
        duration: 0.9,
        ease: 'power2.out',
        stagger: 0.12,
        delay: 0.2,
      });

      if (heroVisualRef.current) {
        gsap.from(heroVisualRef.current, {
          opacity: 0,
          duration: 0.9,
          ease: 'power2.out',
          delay: 0.6,
        });
      }

      const revealSection = (sectionRef: any, targetRefs: Array<any>) => {
        const validTargets = targetRefs.filter(Boolean);
        if (!sectionRef || !validTargets.length) {
          return;
        }

        gsap.from(validTargets as any, {
          scrollTrigger: {
            trigger: sectionRef as any,
            start: 'top 80%',
            end: 'top 40%',
          },
          y: 40,
          opacity: 0,
          duration: 0.9,
          ease: 'power2.out',
          stagger: 0.12,
        });
      };

      revealSection(servicesSectionRef.current, [servicesHeadingRef.current, ...serviceCardRefs.current]);
      revealSection(workSectionRef.current, [workHeadingRef.current, ...projectCardRefs.current]);

      revealSection(whySectionRef.current, [whyHeadingRef.current]);
      revealSection(aboutSectionRef.current, [aboutHeadingRef.current]);
      revealSection(contactSectionRef.current, [contactHeadingRef.current]);

      if (aboutSectionRef.current) {
        ScrollTrigger.create({
          trigger: aboutSectionRef.current as any,
          start: 'top 80%',
          once: true,
          onEnter: () => {
            if (statsAnimated) {
              return;
            }

            setStatsAnimated(true);
            const counters = { projects: 0, services: 0, retention: 0 };

            gsap.to(counters, {
              projects: 15,
              services: 4,
              retention: 100,
              duration: 1.1,
              ease: 'power2.out',
              onUpdate: () => {
                setStats({
                  projects: `${Math.round(counters.projects)}+`,
                  services: `${Math.round(counters.services)}`,
                  retention: `${Math.round(counters.retention)}%`,
                });
              },
            });
          },
        });
      }

      cleanup = () => {
        ScrollTrigger.getAll().forEach((trigger: any) => trigger.kill());
      };
    })();

    return () => {
      mounted = false;
      cleanup();
    };
  }, [statsAnimated]);

  const handleSubmit = async () => {
    const subject = encodeURIComponent(`Project inquiry from ${form.name || 'Edoble site'}`);
    const body = encodeURIComponent([
      `Name: ${form.name}`,
      `Email: ${form.email}`,
      `Service needed: ${form.service}`,
      `Budget: ${form.budget}`,
      '',
      form.message,
    ].join('\n'));

    await Linking.openURL(`mailto:hello@edoble.com?subject=${subject}&body=${body}`);
  };

  const workSectionStart = sectionOffsets.current.work;
  const workAnimationProgress = Math.max(
    0,
    Math.min(1, (scrollY - (workSectionStart - height * 0.2)) / Math.max(height * 0.8, 1))
  );
  const servicesSectionStart = sectionOffsets.current.services;
  const servicesAnimationProgress = Math.max(
    0,
    Math.min(1, (scrollY - (servicesSectionStart - height * 0.1)) / Math.max(height * 1.2, 1))
  );
  const servicesShiftProgress = Math.min(1, servicesAnimationProgress / 0.5);
  const servicesScaleProgress = Math.max(0, (servicesAnimationProgress - 0.5) / 0.5);
  const servicesMinScale = width <= 960 ? 0.3 : 0.1;
  const servicesScale = 1 - servicesScaleProgress * (1 - servicesMinScale);

  return (
    <View style={styles.page}>
      <StatusBar style="dark" />

      <View style={[styles.nav, scrolled ? styles.navScrolled : null]}>
        <View style={styles.navInner}>
          <Pressable onPress={() => scrollToSection('services')} style={styles.brandWrap}>
            <LogoMark size={34} />
            <View>
              <Text style={styles.brandName}>Edoble</Text>
              <Text style={styles.brandTag}>Digital Craft. Delivered.</Text>
            </View>
          </Pressable>

          {isDesktop ? (
            <View style={styles.navLinks}>
              {navItems.map((item) => (
                <Pressable key={item.label} onPress={() => scrollToSection(item.key)} style={styles.navLinkButton}>
                  <Text style={styles.navLink}>{item.label}</Text>
                </Pressable>
              ))}
            </View>
          ) : null}

          <View style={styles.navRight}>
            {isDesktop ? (
              <Pressable onPress={() => scrollToSection('contact')} style={styles.navCta}>
                <Text style={styles.navCtaText}>Start a Project</Text>
              </Pressable>
            ) : (
              <Pressable onPress={() => setMenuOpen((current) => !current)} style={styles.menuButton}>
                <View style={[styles.menuLine, menuOpen ? styles.menuLineTopOpen : null]} />
                <View style={[styles.menuLine, menuOpen ? styles.menuLineMiddleOpen : null]} />
                <View style={[styles.menuLine, menuOpen ? styles.menuLineBottomOpen : null]} />
              </Pressable>
            )}
          </View>
        </View>
      </View>

      <ScrollView
        ref={scrollRef}
        onScroll={(event) => {
          const nextScrollY = event.nativeEvent.contentOffset.y;
          setScrolled(nextScrollY > 60);
          setScrollY(nextScrollY);
        }}
        scrollEventThrottle={16}
        showsVerticalScrollIndicator={false}
        contentContainerStyle={styles.scrollContent}
      >
        <View style={[styles.heroSection, { minHeight: height }]}>
          <View style={[styles.container, styles.heroGrid, !isDesktop ? styles.heroGridStack : null]}>
            <View style={[styles.heroCopyColumn, !isDesktop ? styles.heroCopyColumnMobile : null]}>
              <View ref={heroEyebrowRef} style={styles.heroEyebrowRow}>
                <View style={styles.heroEyebrowRule} />
                <Text style={styles.heroEyebrow}>Digital Agency · Est. 2024</Text>
              </View>

              <View style={styles.heroTitleBlock}>
                <Text ref={heroLineOneRef} style={styles.heroTitleLine}>
                  We Build Digital Products That Work.
                </Text>
                <Text ref={heroLineTwoRef} style={[styles.heroTitleLine, styles.heroTitleItalic]}>
                  And Look Like They Do.
                </Text>
              </View>

              <Text ref={heroCopyRef} style={styles.heroCopy}>
                Edoble delivers websites, apps, and brand identities for businesses that refuse to look ordinary.
              </Text>

              <View ref={heroActionsRef} style={styles.heroActions}>
                <Pressable onPress={() => scrollToSection('work')} style={styles.primaryButton}>
                  <Text style={styles.primaryButtonText}>View Our Work</Text>
                  <Text style={styles.primaryButtonArrow}>→</Text>
                </Pressable>
                <Pressable onPress={() => scrollToSection('contact')} style={styles.secondaryButton}>
                  <Text style={styles.secondaryButtonText}>Let's Talk</Text>
                </Pressable>
              </View>
            </View>

            <View ref={heroVisualRef} style={[styles.heroVisualColumn, !isDesktop ? styles.heroVisualColumnMobile : null]}>
              <View style={styles.visualFrame}>
                <View style={styles.visualGhostWrap}>
                  <LogoMark size={280} subtle />
                </View>
                <View style={styles.visualCore}>
                  <View style={styles.visualCircle}>
                    <View style={styles.visualCircleInner}>
                      <Text style={styles.visualWordmark}>Edoble</Text>
                      <Text style={styles.visualWordmarkSub}>Digital Craft. Delivered.</Text>
                    </View>
                  </View>

                  <View style={[styles.microLabel, styles.microTop]}>
                    <Text style={styles.microLabelText}>Web Dev</Text>
                  </View>
                  <View style={[styles.microLabel, styles.microRight]}>
                    <Text style={styles.microLabelText}>App Dev</Text>
                  </View>
                  <View style={[styles.microLabel, styles.microBottom]}>
                    <Text style={styles.microLabelText}>UI/UX</Text>
                  </View>
                  <View style={[styles.microLabel, styles.microLeft]}>
                    <Text style={styles.microLabelText}>Branding</Text>
                  </View>
                </View>
              </View>
            </View>
          </View>
        </View>

        <View ref={servicesSectionRef} onLayout={handleSectionLayout('services')} style={[styles.section, styles.sectionSoft]}>
          <View style={styles.container}>
            <View style={styles.servicesStage}>
              <View
                style={[
                  styles.servicesHeaderRow,
                  styles.servicesHeaderLeft,
                  { transform: [{ translateX: width * (1 - servicesShiftProgress) }, { scale: servicesScale }] },
                ]}>
                <Text style={styles.servicesHeaderText}>Website Development</Text>
              </View>
              <View
                style={[
                  styles.servicesHeaderRow,
                  styles.servicesHeaderCenter,
                  { transform: [{ translateX: -width * (1 - servicesShiftProgress) }, { scale: servicesScale }] },
                ]}>
                <Text style={styles.servicesHeaderText}>App Development</Text>
              </View>
              <View
                style={[
                  styles.servicesHeaderRow,
                  styles.servicesHeaderRight,
                  { transform: [{ translateX: width * (1 - servicesShiftProgress) }, { scale: servicesScale }] },
                ]}>
                <Text style={styles.servicesHeaderText}>UI/UX Design</Text>
              </View>

              <View style={styles.servicesCopyWrap}>
                <SectionHeading
                  eyebrow="What We Do"
                  title="Every Service You Need. One Team."
                  body="From the first wireframe to the final deployment - we handle it all."
                  titleRef={(node) => {
                    servicesHeadingRef.current = node;
                  }}
                />
              </View>

              <View style={styles.servicesGrid}>
                {serviceCards.map((item, index) => (
                  <ServiceCard key={item.title} item={item} index={index} register={registerServiceCard} />
                ))}
              </View>
            </View>
          </View>
        </View>

        <View ref={workSectionRef} onLayout={handleSectionLayout('work')} style={[styles.section, styles.sectionWhite]}>
          <View style={styles.container}>
            <SectionHeading
              eyebrow="Selected Work"
              title="Projects That Earned Their Place Here."
              titleRef={(node) => {
                workHeadingRef.current = node;
              }}
            />

            {isDesktop ? (
              <View style={styles.projectsGrid}>
                <View style={styles.workScene}>
                  {/* Titles horizontal strip (wide) */}
                  <View
                    ref={workTitlesRef}
                    style={[
                      styles.titlesStrip,
                      {
                        width: width * projectCards.length,
                        transform: [{ translateX: -(workAnimationProgress * width * (projectCards.length - 1)) }],
                      },
                    ]}>
                    {projectCards.map((item, i) => (
                      <View key={`title-${i}`} style={[styles.titlePanel, { width }]}>
                        <Text style={styles.titleStripText}>{item.title}</Text>
                      </View>
                    ))}
                  </View>

                  {/* Images horizontal strip (wide) */}
                  <View
                    ref={workImagesRef}
                    style={[
                      styles.imagesStrip,
                      {
                        width: width * projectCards.length,
                        transform: [{ translateX: workAnimationProgress * width }],
                      },
                    ]}>
                    {projectCards.map((item, index) => (
                      <View key={`img-${index}`} style={[styles.imagePanel, { width }]}>
                        <ProjectCard item={item} index={index} register={registerProjectCard} />
                      </View>
                    ))}
                  </View>
                </View>
              </View>
            ) : (
              <View style={styles.projectsStack}>
                {projectCards.map((item, index) => (
                  <ProjectCard key={item.title} item={item} index={index} register={registerProjectCard} />
                ))}
              </View>
            )}
          </View>
        </View>

        <View ref={whySectionRef} onLayout={handleSectionLayout('why')} style={[styles.section, styles.sectionDark]}>
          <View style={styles.container}>
            <SectionHeading eyebrow="Our Edge" title="Why Clients Choose Edoble." dark titleRef={(node) => {
              whyHeadingRef.current = node;
            }} />

            <View style={styles.advantageGrid}>
              {advantages.map((item) => (
                <View key={item.title} style={styles.advantageCard}>
                  <View style={styles.advantageRule} />
                  <Text style={styles.advantageTitle}>{item.title}</Text>
                  <Text style={styles.advantageText}>{item.description}</Text>
                </View>
              ))}
            </View>

            <View style={styles.centerCtaWrap}>
              <Pressable onPress={() => scrollToSection('contact')} style={styles.accentButton}>
                <Text style={styles.accentButtonText}>Start Your Project</Text>
              </Pressable>
            </View>
          </View>
        </View>

        <View ref={aboutSectionRef} onLayout={handleSectionLayout('about')} style={[styles.section, styles.sectionSoft]}>
          <View style={styles.container}>
            <View style={styles.aboutGrid}>
              <View style={styles.aboutCopyColumn}>
                <SectionHeading
                  eyebrow="About Edoble"
                  title="A Small Team. Uncompromising Standards."
                  body="Edoble is a digital agency built for businesses that take their online presence seriously. We don't do average work - not because we can't, but because we won't. Every project gets our full attention. Every pixel gets a reason."
                  titleRef={(node) => {
                    aboutHeadingRef.current = node;
                  }}
                />

                <View style={styles.statsRow}>
                  <StatBlock value={stats.projects} label="Projects" />
                  <StatBlock value={stats.services} label="Services" />
                  <StatBlock value={stats.retention} label="Client retention" />
                </View>
              </View>

              <View style={styles.aboutVisual}>
                <View style={styles.aboutImageFrame}>
                  <View style={styles.aboutImageAccent} />
                  <View style={styles.aboutImageCore}>
                    <Text style={styles.aboutImageWordmark}>Edoble</Text>
                    <Text style={styles.aboutImageCaption}>Crafted web systems for brands that want their presence to feel deliberate.</Text>
                  </View>
                </View>
              </View>
            </View>
          </View>
        </View>

        <View ref={contactSectionRef} onLayout={handleSectionLayout('contact')} style={[styles.section, styles.sectionWhite, styles.contactSection]}>
          <View style={styles.container}>
            <View style={styles.contactGrid}>
              <View style={styles.contactLeft}>
                <SectionHeading
                  eyebrow="Let's Build"
                  title="Have a Project in Mind?"
                  body="Tell us what you're building. We'll tell you how we'd build it better."
                  titleRef={(node) => {
                    contactHeadingRef.current = node;
                  }}
                />

                <View style={styles.contactDetails}>
                  <View style={styles.contactDetailRow}>
                    <Feather name="mail" size={18} color={brand.accent} />
                    <Text style={styles.contactDetailText}>hello@edoble.com</Text>
                  </View>
                  <View style={styles.contactDetailRow}>
                    <Feather name="clock" size={18} color={brand.accent} />
                    <Text style={styles.contactDetailText}>We reply within 24 hours</Text>
                  </View>
                </View>
              </View>

              <View style={styles.contactFormCard}>
                <View style={styles.formGrid}>
                  <FormField label="Full Name" value={form.name} onChangeText={(value) => setForm((current) => ({ ...current, name: value }))} placeholder="Your name" />
                  <FormField label="Email Address" value={form.email} onChangeText={(value) => setForm((current) => ({ ...current, email: value }))} placeholder="you@company.com" keyboardType="email-address" />
                  <SelectField label="Service Needed" value={form.service} placeholder="Select a service" options={serviceOptions} onChange={(value) => setForm((current) => ({ ...current, service: value }))} />
                  <SelectField label="Project Budget" value={form.budget} placeholder="Select a budget" options={budgetOptions} onChange={(value) => setForm((current) => ({ ...current, budget: value }))} />
                  <FormField label="Message" value={form.message} onChangeText={(value) => setForm((current) => ({ ...current, message: value }))} placeholder="Tell us about the project" multiline />
                </View>

                <Pressable onPress={handleSubmit} style={styles.submitButton}>
                  <Text style={styles.submitButtonText}>Send Message →</Text>
                </Pressable>
              </View>
            </View>
          </View>
        </View>

        <View style={styles.footer}>
          <View style={styles.container}>
            <View style={styles.footerGrid}>
              <View>
                <Pressable onPress={() => scrollToSection('services')} style={styles.footerBrandRow}>
                  <LogoMark size={34} subtle={false} />
                  <View>
                    <Text style={styles.footerBrand}>Edoble</Text>
                    <Text style={styles.footerTag}>Digital Craft. Delivered.</Text>
                  </View>
                </Pressable>
                <Text style={styles.footerCopy}>© 2024 Edoble. All rights reserved.</Text>
              </View>

              <View>
                <Text style={styles.footerHeading}>Services</Text>
                <View style={styles.footerLinkList}>
                  {footerColumns.services.map((label) => (
                    <Text key={label} style={styles.footerLinkText}>
                      {label}
                    </Text>
                  ))}
                </View>
              </View>

              <View>
                <Text style={styles.footerHeading}>Company</Text>
                <View style={styles.footerLinkList}>
                  {footerColumns.company.map((label) => (
                    <Pressable
                      key={label}
                      onPress={() => scrollToSection(label === 'About' ? 'about' : label === 'Work' ? 'work' : 'contact')}>
                      <Text style={styles.footerLinkText}>{label}</Text>
                    </Pressable>
                  ))}
                </View>
              </View>

              <View>
                <Text style={styles.footerHeading}>Social</Text>
                <View style={styles.socialRow}>
                  <SocialLink icon="linkedin" href="https://www.linkedin.com" label="LinkedIn" />
                  <SocialLink icon="instagram" href="https://www.instagram.com" label="Instagram" />
                  <SocialLink icon="briefcase" href="https://www.behance.net" label="Behance" />
                  <SocialLink icon="github" href="https://github.com" label="GitHub" />
                </View>
              </View>
            </View>

            <View style={styles.footerBottom}>
              <Text style={styles.footerBottomText}>© 2024 Edoble. All rights reserved.</Text>
              <Text style={styles.footerBottomText}>Designed & Built by Edoble</Text>
            </View>
          </View>
        </View>
      </ScrollView>

      <Modal visible={menuOpen} animationType="fade" transparent>
        <View style={styles.menuOverlay}>
          <View style={styles.menuOverlayInner}>
            <View style={styles.menuOverlayTopRow}>
              <Text style={styles.menuOverlayTitle}>Edoble</Text>
              <Pressable onPress={() => setMenuOpen(false)} style={styles.menuCloseButton}>
                <Feather name="x" size={28} color="#FFFFFF" />
              </Pressable>
            </View>

            <View style={styles.menuList}>
              {mobileMenuItems.map((item) => (
                <Pressable key={item.label} onPress={() => scrollToSection(item.key)} style={styles.menuItem}>
                  <Text style={styles.menuItemText}>{item.label}</Text>
                </Pressable>
              ))}
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  page: {
    flex: 1,
    backgroundColor: brand.background,
  },
  nav: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    zIndex: 100,
    height: 72,
    justifyContent: 'center',
    borderBottomWidth: 1,
    borderBottomColor: 'transparent',
    backgroundColor: 'transparent',
  },
  navScrolled: {
    backgroundColor: 'rgba(247,246,242,0.92)',
    borderBottomColor: brand.border,
  },
  navInner: {
    width: '100%',
    maxWidth: 1200,
    paddingHorizontal: 40,
    alignSelf: 'center',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 16,
  },
  brandWrap: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    minWidth: 180,
  },
  brandName: {
    color: brand.text,
    fontFamily: 'Inter_500Medium',
    fontSize: 14,
    letterSpacing: 0.04,
  },
  brandTag: {
    color: brand.muted,
    fontSize: 11,
    fontFamily: 'Inter_400Regular',
    marginTop: 1,
  },
  navLinks: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  navLinkButton: {
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  navLink: {
    color: brand.text,
    fontFamily: 'Inter_500Medium',
    fontSize: 14,
  },
  navRight: {
    minWidth: 180,
    alignItems: 'flex-end',
  },
  navCta: {
    backgroundColor: brand.text,
    borderRadius: 999,
    paddingHorizontal: 24,
    paddingVertical: 12,
  },
  navCtaText: {
    color: brand.background,
    fontSize: 14,
    fontFamily: 'Inter_500Medium',
  },
  menuButton: {
    width: 48,
    height: 48,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 4,
  },
  menuLine: {
    width: 22,
    height: 2,
    borderRadius: 999,
    backgroundColor: brand.text,
  },
  menuLineTopOpen: {
    transform: [{ translateY: 6 }, { rotate: '45deg' }],
  },
  menuLineMiddleOpen: {
    opacity: 0,
  },
  menuLineBottomOpen: {
    transform: [{ translateY: -6 }, { rotate: '-45deg' }],
  },
  scrollContent: {
    paddingTop: 72,
  },
  container: {
    width: '100%',
    maxWidth: 1200,
    alignSelf: 'center',
    paddingHorizontal: 40,
  },
  section: {
    paddingVertical: 160,
  },
  sectionSoft: {
    backgroundColor: brand.background,
  },
  sectionWhite: {
    backgroundColor: brand.surface,
  },
  sectionDark: {
    backgroundColor: brand.text,
  },
  heroSection: {
    justifyContent: 'center',
    paddingVertical: 48,
    backgroundColor: brand.background,
  },
  heroGrid: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 32,
  },
  heroGridStack: {
    flexDirection: 'column',
    alignItems: 'stretch',
  },
  heroCopyColumn: {
    flex: 0.58,
    gap: 16,
  },
  heroCopyColumnMobile: {
    width: '100%',
  },
  heroEyebrowRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  heroEyebrowRule: {
    width: 24,
    height: 1,
    backgroundColor: brand.accent,
  },
  heroEyebrow: {
    color: brand.muted,
    fontFamily: 'Inter_500Medium',
    fontSize: 11,
    letterSpacing: 1.65,
    textTransform: 'uppercase',
  },
  heroTitleBlock: {
    gap: 6,
  },
  heroTitleLine: {
    color: brand.text,
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 72,
    lineHeight: 76,
    letterSpacing: -1.44,
  },
  heroTitleItalic: {
    fontStyle: 'italic',
  },
  heroCopy: {
    maxWidth: 480,
    color: brand.muted,
    fontFamily: 'Inter_400Regular',
    fontSize: 17,
    lineHeight: 30,
  },
  heroActions: {
    flexDirection: 'row',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 16,
    marginTop: 24,
  },
  primaryButton: {
    backgroundColor: brand.text,
    borderRadius: 999,
    paddingHorizontal: 36,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  primaryButtonText: {
    color: brand.surface,
    fontFamily: 'Inter_500Medium',
    fontSize: 15,
  },
  primaryButtonArrow: {
    color: brand.surface,
    fontFamily: 'Inter_500Medium',
    fontSize: 16,
  },
  secondaryButton: {
    backgroundColor: 'transparent',
    borderWidth: 1.5,
    borderColor: brand.text,
    borderRadius: 999,
    paddingHorizontal: 36,
    paddingVertical: 16,
  },
  secondaryButtonText: {
    color: brand.text,
    fontFamily: 'Inter_500Medium',
    fontSize: 15,
  },
  heroVisualColumn: {
    flex: 0.42,
    alignItems: 'center',
    justifyContent: 'center',
  },
  heroVisualColumnMobile: {
    width: '100%',
    marginTop: 24,
  },
  visualFrame: {
    width: '100%',
    aspectRatio: 1,
    minHeight: 420,
    alignItems: 'center',
    justifyContent: 'center',
  },
  visualGhostWrap: {
    position: 'absolute',
    alignItems: 'center',
    justifyContent: 'center',
  },
  visualCore: {
    width: '100%',
    maxWidth: 420,
    aspectRatio: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  visualCircle: {
    width: '88%',
    aspectRatio: 1,
    borderRadius: 999,
    borderWidth: 1,
    borderColor: brand.border,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(255,255,255,0.34)',
    boxShadow: '0px 12px 24px rgba(0,0,0,0.08)',
  },
  visualCircleInner: {
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  visualWordmark: {
    color: brand.text,
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 48,
    lineHeight: 52,
  },
  visualWordmarkSub: {
    color: brand.muted,
    fontFamily: 'Inter_500Medium',
    fontSize: 11,
    letterSpacing: 1.3,
    textTransform: 'uppercase',
  },
  microLabel: {
    position: 'absolute',
    backgroundColor: brand.surface,
    borderWidth: 1,
    borderColor: brand.border,
    paddingHorizontal: 14,
    paddingVertical: 6,
    borderRadius: 999,
  },
  microLabelText: {
    color: brand.text,
    fontFamily: 'Inter_500Medium',
    fontSize: 11,
    letterSpacing: 1.1,
    textTransform: 'uppercase',
  },
  microTop: {
    top: 18,
  },
  microRight: {
    right: 18,
    top: '44%',
  },
  microBottom: {
    bottom: 18,
  },
  microLeft: {
    left: 18,
    top: '44%',
  },
  logoMark: {
    borderWidth: 1,
    borderColor: brand.border,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: brand.surface,
  },
  logoLetter: {
    color: brand.text,
    fontFamily: 'DMSerifDisplay_400Regular',
    lineHeight: 1,
  },
  headingBlock: {
    maxWidth: 560,
    gap: 16,
    marginBottom: 40,
  },
  centerAlign: {
    alignItems: 'center',
  },
  centerJustify: {
    justifyContent: 'center',
  },
  eyebrowRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  eyebrowRule: {
    width: 24,
    height: 1,
    backgroundColor: brand.accent,
  },
  eyebrowRuleDark: {
    backgroundColor: brand.accent,
  },
  eyebrow: {
    color: brand.muted,
    fontFamily: 'Inter_500Medium',
    fontSize: 11,
    letterSpacing: 1.65,
    textTransform: 'uppercase',
  },
  eyebrowDark: {
    color: 'rgba(255,255,255,0.72)',
  },
  sectionTitle: {
    color: brand.text,
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 48,
    lineHeight: 58,
    letterSpacing: -0.96,
  },
  sectionTitleDark: {
    color: '#FFFFFF',
  },
  sectionBody: {
    color: brand.muted,
    fontFamily: 'Inter_400Regular',
    fontSize: 16,
    lineHeight: 28,
    maxWidth: 560,
  },
  sectionBodyDark: {
    color: 'rgba(255,255,255,0.6)',
  },
  centerText: {
    textAlign: 'center',
  },
  servicesGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 24,
  },
  servicesStage: {
    position: 'relative',
    overflow: 'hidden',
    paddingTop: 24,
    paddingBottom: 16,
  },
  servicesCopyWrap: {
    paddingTop: 136,
    paddingBottom: 36,
  },
  servicesHeaderRow: {
    position: 'absolute',
    left: 0,
    right: 0,
    minHeight: 128,
    paddingHorizontal: 24,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: brand.background,
  },
  servicesHeaderLeft: {
    top: 0,
  },
  servicesHeaderCenter: {
    top: 112,
    zIndex: 2,
  },
  servicesHeaderRight: {
    top: 224,
  },
  servicesHeaderText: {
    color: brand.text,
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 72,
    lineHeight: 76,
    letterSpacing: -1.6,
    textAlign: 'center',
  },
  serviceCard: {
    flexGrow: 1,
    flexBasis: 0,
    minWidth: 280,
    backgroundColor: brand.surface,
    borderWidth: 1,
    borderColor: brand.border,
    borderRadius: 20,
    padding: 40,
    minHeight: 280,
    overflow: 'hidden',
  },
  serviceCardHover: {
    borderColor: brand.accent,
    boxShadow: '0px 8px 40px rgba(0,0,0,0.06)',
  },
  serviceNumber: {
    position: 'absolute',
    top: 20,
    right: 24,
    color: '#E8E6E0',
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 48,
    lineHeight: 48,
  },
  serviceIconWrap: {
    width: 56,
    height: 56,
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 16,
    backgroundColor: 'rgba(201,169,110,0.12)',
    marginBottom: 20,
  },
  serviceTitle: {
    color: brand.text,
    fontFamily: 'Inter_500Medium',
    fontSize: 20,
    lineHeight: 28,
    marginBottom: 12,
  },
  serviceDescription: {
    color: brand.muted,
    fontFamily: 'Inter_400Regular',
    fontSize: 15,
    lineHeight: 26,
    maxWidth: 320,
  },
  cardLink: {
    color: brand.accent,
    fontFamily: 'Inter_500Medium',
    fontSize: 13,
    marginTop: 'auto',
    opacity: 0,
    transform: [{ translateY: 8 }],
  },
  cardLinkVisible: {
    opacity: 1,
    transform: [{ translateY: 0 }],
  },
  projectsGrid: {
    position: 'relative',
    minHeight: 760,
    overflow: 'hidden',
    backgroundColor: '#FFFDF7',
    borderRadius: 28,
    borderWidth: 1,
    borderColor: brand.border,
  },
  workScene: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
  },
  projectsStack: {
    gap: 24,
  },
  projectCard: {
    flex: 1,
    borderRadius: 20,
    overflow: 'hidden',
    minHeight: 280,
    backgroundColor: '#F0EADF',
  },
  projectLarge: {
    aspectRatio: 16 / 9,
  },
  projectSmall: {
    aspectRatio: 4 / 3,
  },
  projectVisual: {
    flex: 1,
    justifyContent: 'center',
    overflow: 'hidden',
  },
  projectOrb: {
    position: 'absolute',
    right: -40,
    top: -40,
    width: 160,
    height: 160,
    borderRadius: 999,
    backgroundColor: 'rgba(255,255,255,0.15)',
  },
  projectRibbon: {
    position: 'absolute',
    alignSelf: 'center',
    borderRadius: 999,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.45)',
    backgroundColor: 'rgba(255,255,255,0.12)',
  },
  projectRibbonLarge: {
    paddingHorizontal: 22,
    paddingVertical: 10,
  },
  projectRibbonSmall: {
    paddingHorizontal: 18,
    paddingVertical: 8,
  },
  projectRibbonText: {
    color: '#FFFFFF',
    fontFamily: 'Inter_500Medium',
    fontSize: 11,
    letterSpacing: 1,
    textTransform: 'uppercase',
  },
  projectBar: {
    backgroundColor: '#FFFFFF',
    paddingHorizontal: 20,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 16,
  },
  projectBarText: {
    gap: 4,
  },
  projectName: {
    color: brand.text,
    fontFamily: 'Inter_500Medium',
    fontSize: 15,
  },
  projectCategory: {
    color: brand.muted,
    fontFamily: 'Inter_400Regular',
    fontSize: 12,
  },
  projectArrow: {
    color: brand.accent,
    fontFamily: 'Inter_500Medium',
    fontSize: 18,
  },
  projectOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: brand.overlay,
    padding: 24,
    justifyContent: 'flex-end',
    opacity: 0,
    transform: [{ translateY: 24 }],
  },
  projectOverlayVisible: {
    opacity: 1,
    transform: [{ translateY: 0 }],
  },
  projectOverlayTitle: {
    color: '#FFFFFF',
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 24,
    lineHeight: 30,
    marginBottom: 16,
  },
  tagRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 18,
  },
  tagPill: {
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.55)',
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 6,
  },
  tagText: {
    color: '#FFFFFF',
    fontFamily: 'Inter_500Medium',
    fontSize: 11,
    letterSpacing: 0.9,
    textTransform: 'uppercase',
  },
  projectOverlayLink: {
    color: brand.accent,
    fontFamily: 'Inter_500Medium',
    fontSize: 13,
  },
  titlesStrip: {
    flexDirection: 'row',
    position: 'absolute',
    top: 28,
    left: 0,
    height: 180,
    alignItems: 'center',
  },
  titlePanel: {
    width: '100%',
    alignItems: 'center',
    justifyContent: 'center',
  },
  titleStripText: {
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 72,
    fontStyle: 'italic',
    letterSpacing: -1.2,
    color: brand.text,
  },
  imagesStrip: {
    flexDirection: 'row',
    position: 'absolute',
    left: 0,
    top: '50%',
    height: 460,
    alignItems: 'center',
    transform: [{ translateY: -60 }],
  },
  imagePanel: {
    width: '100%',
    paddingHorizontal: 40,
    justifyContent: 'center',
  },
  advantageGrid: {
    flexDirection: 'row',
    gap: 32,
  },
  advantageCard: {
    flex: 1,
  },
  advantageRule: {
    width: 40,
    height: 1,
    backgroundColor: brand.accent,
    marginBottom: 20,
  },
  advantageTitle: {
    color: '#FFFFFF',
    fontFamily: 'Inter_500Medium',
    fontSize: 18,
    lineHeight: 26,
    marginBottom: 10,
  },
  advantageText: {
    color: 'rgba(255,255,255,0.6)',
    fontFamily: 'Inter_400Regular',
    fontSize: 15,
    lineHeight: 26,
  },
  centerCtaWrap: {
    marginTop: 64,
    alignItems: 'center',
  },
  accentButton: {
    backgroundColor: brand.accent,
    borderRadius: 999,
    paddingHorizontal: 32,
    paddingVertical: 16,
  },
  accentButtonText: {
    color: brand.text,
    fontFamily: 'Inter_500Medium',
    fontSize: 15,
  },
  aboutGrid: {
    flexDirection: 'row',
    gap: 32,
    alignItems: 'center',
  },
  aboutCopyColumn: {
    flex: 1,
  },
  statsRow: {
    flexDirection: 'row',
    gap: 20,
    marginTop: 24,
    flexWrap: 'wrap',
  },
  statBlock: {
    minWidth: 150,
    paddingTop: 20,
  },
  statValue: {
    color: brand.text,
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 32,
    lineHeight: 34,
    marginBottom: 6,
  },
  statLabel: {
    color: brand.muted,
    fontFamily: 'Inter_400Regular',
    fontSize: 13,
  },
  aboutVisual: {
    flex: 1,
  },
  aboutImageFrame: {
    minHeight: 420,
    borderRadius: 20,
    backgroundColor: '#E7E1D4',
    overflow: 'hidden',
    justifyContent: 'center',
    alignItems: 'center',
  },
  aboutImageAccent: {
    position: 'absolute',
    top: -60,
    right: -40,
    width: 220,
    height: 220,
    borderRadius: 999,
    backgroundColor: 'rgba(20,20,20,0.08)',
  },
  aboutImageCore: {
    padding: 32,
    alignItems: 'center',
    gap: 12,
  },
  aboutImageWordmark: {
    color: brand.text,
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 56,
    lineHeight: 60,
  },
  aboutImageCaption: {
    maxWidth: 320,
    color: brand.muted,
    fontFamily: 'Inter_400Regular',
    fontSize: 15,
    lineHeight: 25,
    textAlign: 'center',
  },
  contactSection: {
    paddingBottom: 120,
  },
  contactGrid: {
    flexDirection: 'row',
    gap: 32,
    alignItems: 'flex-start',
  },
  contactLeft: {
    flex: 0.42,
  },
  contactDetails: {
    gap: 14,
    marginTop: 16,
  },
  contactDetailRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  contactDetailText: {
    color: brand.text,
    fontFamily: 'Inter_400Regular',
    fontSize: 15,
  },
  contactFormCard: {
    flex: 0.58,
    backgroundColor: brand.surface,
    borderWidth: 1,
    borderColor: brand.border,
    borderRadius: 20,
    padding: 36,
  },
  formGrid: {
    gap: 20,
  },
  fieldGroup: {
    gap: 8,
  },
  fieldLabel: {
    color: brand.text,
    fontFamily: 'Inter_500Medium',
    fontSize: 13,
  },
  textInput: {
    backgroundColor: brand.background,
    borderWidth: 1.5,
    borderColor: brand.border,
    borderRadius: 12,
    paddingHorizontal: 20,
    paddingVertical: 16,
    color: brand.text,
    fontFamily: 'Inter_400Regular',
    fontSize: 15,
    minHeight: 56,
  },
  textArea: {
    minHeight: 120,
    textAlignVertical: 'top',
  },
  inputText: {
    color: brand.text,
    fontFamily: 'Inter_400Regular',
    fontSize: 15,
  },
  placeholderText: {
    color: '#9B988F',
  },
  selectTrigger: {
    backgroundColor: brand.background,
    borderWidth: 1.5,
    borderColor: brand.border,
    borderRadius: 12,
    paddingHorizontal: 20,
    paddingVertical: 16,
    minHeight: 56,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 16,
  },
  selectMenu: {
    backgroundColor: brand.surface,
    borderWidth: 1,
    borderColor: brand.border,
    borderRadius: 14,
    overflow: 'hidden',
  },
  selectOption: {
    paddingHorizontal: 18,
    paddingVertical: 14,
    borderBottomWidth: 1,
    borderBottomColor: brand.border,
  },
  selectOptionText: {
    color: brand.text,
    fontFamily: 'Inter_400Regular',
    fontSize: 15,
  },
  submitButton: {
    alignSelf: 'flex-start',
    backgroundColor: brand.text,
    borderRadius: 999,
    paddingHorizontal: 32,
    paddingVertical: 16,
    marginTop: 24,
  },
  submitButtonText: {
    color: brand.background,
    fontFamily: 'Inter_500Medium',
    fontSize: 15,
  },
  footer: {
    backgroundColor: brand.text,
    paddingTop: 84,
    paddingBottom: 28,
  },
  footerGrid: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 32,
    flexWrap: 'wrap',
  },
  footerBrandRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 18,
  },
  footerBrand: {
    color: '#FFFFFF',
    fontFamily: 'Inter_500Medium',
    fontSize: 14,
  },
  footerTag: {
    color: 'rgba(255,255,255,0.6)',
    fontFamily: 'Inter_400Regular',
    fontSize: 11,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  footerCopy: {
    color: 'rgba(255,255,255,0.4)',
    fontFamily: 'Inter_400Regular',
    fontSize: 13,
  },
  footerHeading: {
    color: '#FFFFFF',
    fontFamily: 'Inter_500Medium',
    fontSize: 13,
    marginBottom: 16,
    letterSpacing: 0.6,
    textTransform: 'uppercase',
  },
  footerLinkList: {
    gap: 10,
  },
  footerLinkText: {
    color: 'rgba(255,255,255,0.72)',
    fontFamily: 'Inter_400Regular',
    fontSize: 14,
  },
  socialRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  socialLink: {
    width: 38,
    height: 38,
    borderRadius: 999,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.15)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  footerBottom: {
    marginTop: 42,
    paddingTop: 18,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255,255,255,0.1)',
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 16,
    flexWrap: 'wrap',
  },
  footerBottomText: {
    color: 'rgba(255,255,255,0.4)',
    fontFamily: 'Inter_400Regular',
    fontSize: 13,
  },
  menuOverlay: {
    flex: 1,
    backgroundColor: brand.text,
    paddingTop: 56,
    paddingHorizontal: 28,
    paddingBottom: 40,
  },
  menuOverlayInner: {
    flex: 1,
  },
  menuOverlayTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 56,
  },
  menuOverlayTitle: {
    color: '#FFFFFF',
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 32,
  },
  menuCloseButton: {
    width: 48,
    height: 48,
    alignItems: 'center',
    justifyContent: 'center',
  },
  menuList: {
    flex: 1,
    justifyContent: 'center',
    gap: 18,
  },
  menuItem: {
    paddingVertical: 4,
  },
  menuItemText: {
    color: '#FFFFFF',
    fontFamily: 'DMSerifDisplay_400Regular',
    fontSize: 44,
    lineHeight: 52,
  },
}) as unknown as { [key: string]: any };
